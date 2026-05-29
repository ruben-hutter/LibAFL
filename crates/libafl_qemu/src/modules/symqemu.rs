//! Module for SymQEMU integration with snapshot-based symbolic execution

use std::{cell::OnceCell, ffi::CString};

use libafl::{executors::ExitKind, observers::ObserversTuple};
use libafl_bolts::shmem::{ShMem, ShMemProvider, StdShMem, StdShMemProvider};
use libafl_qemu_sys::GuestAddr;

use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
};

// FFI to SymCC runtime functions
// Note: These will be provided by SymQEMU's runtime when loaded
unsafe extern "C" {
    fn _sym_make_symbolic(addr: *const u8, size: usize, label: *const libc::c_char);
}

/// Module for managing snapshot-based symbolic execution with SymQEMU
///
/// This module integrates LibAFL's snapshot functionality with SymQEMU's symbolic execution.
/// It provides utilities to mark memory regions as symbolic and manage shared memory
/// for constraint passing.
#[derive(Debug)]
pub struct SymQemuModule {
    /// Input buffer address in guest memory
    input_buffer_addr: GuestAddr,

    /// Size of the input buffer
    input_buffer_size: usize,

    /// Shared memory for constraint passing to SymCC runtime
    runtime_shmem: OnceCell<StdShMem>,
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
            runtime_shmem: OnceCell::new(),
        }
    }

    /// Mark the input buffer as symbolic using SymCC runtime
    ///
    /// This should be called after restoring a snapshot to mark the input
    /// buffer as symbolic for SymQEMU to trace.
    pub fn mark_buffer_symbolic(&self) {
        log::info!(
            "Marking buffer at 0x{:x} (size: {}) as symbolic",
            self.input_buffer_addr,
            self.input_buffer_size
        );

        let label = CString::new("input").expect("Failed to create label");

        unsafe {
            _sym_make_symbolic(
                self.input_buffer_addr as *const u8,
                self.input_buffer_size,
                label.as_ptr(),
            );
        }
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
        // Initialize shared memory for SymCC runtime
        const DEFAULT_SIZE: usize = 0x100000; // 1MB for constraint trace
        const DEFAULT_ENV_NAME: &str = "SHARED_MEMORY_MESSAGES";

        let shmem = StdShMemProvider::new()
            .expect("Failed to create shmem provider")
            .new_shmem(DEFAULT_SIZE)
            .expect("Failed to create shared memory");

        unsafe {
            shmem
                .write_to_env(DEFAULT_ENV_NAME)
                .expect("Failed to write shmem to env");
        }

        log::info!("Initialized shared memory for SymCC runtime");
        self.runtime_shmem.set(shmem).ok();
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
        // Nothing to do here for now
    }
}

impl Clone for SymQemuModule {
    fn clone(&self) -> Self {
        Self {
            input_buffer_addr: self.input_buffer_addr,
            input_buffer_size: self.input_buffer_size,
            runtime_shmem: OnceCell::new(),
        }
    }
}
