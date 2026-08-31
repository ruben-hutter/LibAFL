//! Module for SymQEMU integration with snapshot-based symbolic execution
//!
//! This module is used together with the *hybrid* QEMU build (LibAFL bridge +
//! SymQEMU symbolic TCG instrumentation, see `qemu-hybrid/`). The hybrid
//! `libqemu-x86_64.so` links the SymCC C++ shim (`libSymCCRtShared.so`) whose
//! `_rsym_*` symbols stay unresolved at build time and are provided by the host
//! binary at load time (the host links the `runtime` crate from this fuzzer
//! project as an rlib).

use libafl::{executors::ExitKind, observers::ObserversTuple};
use libafl_qemu_sys::GuestAddr;

use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
};

// FFI into the SymCC C++ shim (libSymCCRtShared.so, part of the hybrid QEMU build).
unsafe extern "C" {
    /// Marks `byte_length` bytes at host pointer `data` as symbolic input, with
    /// `input_offset` being the index of the first byte within the symbolic input
    /// (expression indices in the trace will match `input_offset + i`).
    fn _sym_make_symbolic(data: *const core::ffi::c_void, byte_length: usize, input_offset: usize);
    /// Provided by the `runtime` crate (rlib-linked into this very process):
    /// finalize the current concolic trace and start a fresh one.
    fn _libafl_concolic_restart_trace();
}

/// Module for managing snapshot-based symbolic execution with SymQEMU
///
/// It provides utilities to mark memory regions as symbolic between snapshot
/// restores and to delimit per-execution concolic traces.
#[derive(Debug)]
pub struct SymQemuModule {
    /// Input buffer address in guest memory
    input_buffer_addr: GuestAddr,

    /// Size of the input buffer
    input_buffer_size: usize,
}

impl SymQemuModule {
    /// Create a new SymQemuModule
    ///
    /// # Arguments
    /// * `buffer_addr` - Guest address of the input buffer to mark as symbolic
    /// * `buffer_size` - Size of the input buffer
    #[must_use]
    pub fn new(buffer_addr: GuestAddr, buffer_size: usize) -> Self {
        Self {
            input_buffer_addr: buffer_addr,
            input_buffer_size: buffer_size,
        }
    }

    /// Mark the input buffer as symbolic using the SymCC runtime
    ///
    /// This should be called after restoring a snapshot (and after writing the
    /// concrete input bytes into the guest buffer). The guest address is
    /// translated to the corresponding host pointer; the hybrid in-process build
    /// maps guest RAM at host addresses, so the SymCC runtime's shadow memory
    /// keyed by host pointer will match the addresses seen by TCG-generated
    /// symbolic loads.
    pub fn mark_buffer_symbolic(&self, qemu: Qemu) {
        log::info!(
            "Marking buffer at 0x{:x} (size: {}) as symbolic",
            self.input_buffer_addr,
            self.input_buffer_size
        );

        let host_ptr = qemu.g2h::<u8>(self.input_buffer_addr) as *const core::ffi::c_void;
        unsafe {
            // input_offset = 0: expression indices in the concolic trace match
            // the offsets within this buffer (and thus the fuzzer input).
            _sym_make_symbolic(host_ptr, self.input_buffer_size, 0);
        }
    }

    /// Finalize the current concolic trace and start a fresh one.
    ///
    /// Call after each traced execution, before the host reads the trace from
    /// the shared memory region.
    pub fn restart_trace(&self) {
        unsafe { _libafl_concolic_restart_trace() };
    }

    /// Get the buffer address
    #[must_use]
    pub fn buffer_addr(&self) -> GuestAddr {
        self.input_buffer_addr
    }

    /// Get the buffer size
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        self.input_buffer_size
    }

    /// Set the buffer address (for runtime address discovery)
    ///
    /// This is useful when the buffer address is not known at construction time
    /// and needs to be set later (e.g., after discovering malloc'd address via hooks)
    pub fn set_buffer_addr(&mut self, addr: GuestAddr) {
        log::debug!(
            "Updating buffer address from 0x{:x} to 0x{:x}",
            self.input_buffer_addr,
            addr
        );
        self.input_buffer_addr = addr;
    }
}

impl<I, S> EmulatorModule<I, S> for SymQemuModule
where
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        // No shared-memory setup here: the host (fuzzer) creates the concolic
        // shared memory and exports it via SHARED_MEMORY_MESSAGES before the
        // emulator starts. The runtime (rlib-linked into this process) lazily
        // attaches to it on first use. Creating a second region here would
        // overwrite the host's environment variable.
        log::info!("SymQemuModule active (using host-provided concolic shmem)");
    }

    fn post_exec<OT, ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
        ET: EmulatorModuleTuple<I, S>,
    {
        // Finalize the trace written during this execution and prepare a fresh
        // one for the next run.
        self.restart_trace();
    }
}

impl Clone for SymQemuModule {
    fn clone(&self) -> Self {
        Self {
            input_buffer_addr: self.input_buffer_addr,
            input_buffer_size: self.input_buffer_size,
        }
    }
}
