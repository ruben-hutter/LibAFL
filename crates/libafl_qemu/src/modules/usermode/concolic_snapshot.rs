//! Integrated module for snapshot-based symbolic execution
//!
//! This module coordinates SnapshotModule and SymQemuModule to enable
//! persistent symbolic execution with per-input state restoration.
//!
//! Workflow:
//! 1. On first execution, run the target normally until the resolved target function is reached
//! 2. At the target function entry, capture a snapshot and discover the input buffer via register reading
//! 3. On subsequent executions, restore the snapshot, write new input to the buffer, mark it symbolic,
//!    and resume execution from the target function entry

use std::cell::OnceCell;

use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    observers::ObserversTuple,
};
use libafl_bolts::AsSlice;
use libafl_qemu_sys::GuestAddr;

#[cfg(cpu_target = "x86_64")]
use crate::arch::Regs as ArchRegs;
use crate::{
    Qemu,
    elf::EasyElf,
    emu::EmulatorModules,
    modules::{
        EmulatorModule,
        EmulatorModuleTuple,
        usermode::SnapshotModule,
        SymQemuModule,
    },
};

fn snapshot_entry_hook<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + HasTargetBytes,
    S: Unpin,
{
    let module = emulator_modules
        .get_mut::<ConcolicSnapshotModule>()
        .expect("ConcolicSnapshotModule not found in module tuple");

    if module.snapshot_captured {
        return;
    }

    log::info!(
        "Snapshot entry hook triggered at 0x{:x} — capturing snapshot",
        pc
    );

    module.snapshot_module.snapshot(qemu);

    let cpu = qemu.current_cpu().expect("No CPU available");

    #[cfg(cpu_target = "x86_64")]
    {
        let rdi_val: u64 = cpu
            .read_reg(ArchRegs::Rdi)
            .expect("Failed to read RDI")
            .into();
        if rdi_val != 0 {
            log::info!("Discovered input buffer at 0x{:x} from RDI", rdi_val);
            module.input_buffer_addr.set(rdi_val as GuestAddr).ok();
            module
                .symqemu_module
                .set_buffer_addr(rdi_val as GuestAddr);
        } else {
            log::warn!("RDI is NULL at target function entry — buffer address unknown");
        }
    }

    #[cfg(not(cpu_target = "x86_64"))]
    {
        log::warn!(
            "Buffer discovery via register reading not implemented for this architecture"
        );
    }

    module.snapshot_captured = true;
    module.first_execution = false;

    log::info!("Snapshot captured successfully at 0x{:x}", pc);
}

#[derive(Debug)]
pub struct ConcolicSnapshotModule {
    snapshot_module: SnapshotModule,
    symqemu_module: SymQemuModule,
    target_function: String,
    snapshot_address: OnceCell<GuestAddr>,
    input_buffer_addr: OnceCell<GuestAddr>,
    input_buffer_size: usize,
    snapshot_captured: bool,
    first_execution: bool,
}

impl ConcolicSnapshotModule {
    #[must_use]
    pub fn new(target_function: String, buffer_size: usize) -> Self {
        Self {
            snapshot_module: SnapshotModule::new(),
            symqemu_module: SymQemuModule::new(0, buffer_size),
            target_function,
            snapshot_address: OnceCell::new(),
            input_buffer_addr: OnceCell::new(),
            input_buffer_size: buffer_size,
            snapshot_captured: false,
            first_execution: true,
        }
    }

    pub fn set_buffer_address(&mut self, addr: GuestAddr) {
        self.input_buffer_addr.set(addr).ok();
        self.symqemu_module.set_buffer_addr(addr);
    }

    #[must_use]
    pub fn snapshot_address(&self) -> Option<GuestAddr> {
        self.snapshot_address.get().copied()
    }

    #[must_use]
    pub fn is_snapshot_captured(&self) -> bool {
        self.snapshot_captured
    }
}

impl<I, S> EmulatorModule<I, S> for ConcolicSnapshotModule
where
    I: Unpin + HasTargetBytes,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        log::info!(
            "ConcolicSnapshotModule::first_exec — resolving target '{}'",
            self.target_function
        );

        self.symqemu_module.first_exec(qemu, emulator_modules, state);

        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)
            .expect("Failed to load ELF binary");

        let load_addr = qemu.load_addr();
        let target_addr = elf
            .resolve_symbol(&self.target_function, load_addr)
            .unwrap_or_else(|| {
                panic!(
                    "Symbol '{}' not found in binary",
                    self.target_function
                )
            });

        log::info!(
            "Resolved '{}' to 0x{:x} (load_addr=0x{:x})",
            self.target_function,
            target_addr,
            load_addr
        );

        self.snapshot_address.set(target_addr).ok();

        self.snapshot_module.use_manual_reset();

        emulator_modules.instruction_function(
            target_addr,
            snapshot_entry_hook::<ET, I, S>,
            true,
        );

        log::info!(
            "Registered snapshot trigger hook at 0x{:x}",
            target_addr
        );
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.first_execution {
            log::info!(
                "First execution: running to snapshot trigger at 0x{:x}",
                self.snapshot_address.get().copied().unwrap_or(0)
            );
            return;
        }

        if !self.snapshot_captured {
            log::warn!("Snapshot not yet captured — running normally");
            return;
        }

        log::debug!("Restoring snapshot and preparing symbolic execution");

        self.snapshot_module.reset(qemu);

        if let Some(&buffer_addr) = self.input_buffer_addr.get() {
            let target_bytes = input.target_bytes();
            let buf = target_bytes.as_slice();
            let len = buf.len().min(self.input_buffer_size);

            qemu.write_mem(buffer_addr, &buf[..len])
                .expect("Failed to write input to guest memory");

            log::debug!("Wrote {} bytes to buffer at 0x{:x}", len, buffer_addr);

            self.symqemu_module.mark_buffer_symbolic(qemu, len);
            log::debug!("Marked buffer as symbolic for SymQEMU");
        } else {
            log::warn!("Buffer address not discovered — cannot write input or mark symbolic");
        }
    }

    fn post_exec<OT, ET>(
        &mut self,
        qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        state: &mut S,
        input: &I,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        self.symqemu_module.post_exec(
            qemu,
            emulator_modules,
            state,
            input,
            observers,
            exit_kind,
        );
    }
}

impl Clone for ConcolicSnapshotModule {
    fn clone(&self) -> Self {
        Self {
            snapshot_module: SnapshotModule::new(),
            symqemu_module: self.symqemu_module.clone(),
            target_function: self.target_function.clone(),
            snapshot_address: OnceCell::new(),
            input_buffer_addr: OnceCell::new(),
            input_buffer_size: self.input_buffer_size,
            snapshot_captured: false,
            first_execution: true,
        }
    }
}
