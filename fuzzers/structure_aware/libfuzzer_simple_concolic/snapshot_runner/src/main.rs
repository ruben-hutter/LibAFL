//! Standalone smoke test for snapshot-based concolic execution with the
//! hybrid QEMU (LibAFL bridge + SymQEMU symbolic TCG).
//!
//! Flow:
//! 1. Start the emulator on the guest binary and run to `LLVMFuzzerTestOneInput`
//!    (breakpoint). The guest runs "normally" until this entry point.
//! 2. Save the complete CPU state (`CPUArchState`) at the entry breakpoint and
//!    capture a full RAM/mappings snapshot via [`SnapshotModule`]; remember the
//!    input buffer (RDI) and return address.
//! 3. For each test input: restore the snapshot and the saved CPU state, write
//!    the input into the guest buffer, mark it symbolic via the SymCC runtime,
//!    then resume execution until the return-address breakpoint. The symbolic
//!    runtime (rlib-linked into this process) writes a concolic trace into
//!    shared memory; we read it back after every execution and report statistics.
//!
//! Build against the hybrid QEMU tree:
//! ```sh
//! export LIBAFL_QEMU_DIR=$PWD/../qemu-hybrid
//! export LLVM_CONFIG_PATH=/usr/lib/llvm-20/bin/llvm-config
//! export CC=clang CXX=clang++
//! cargo run --release
//! ```

use clap::Parser;
use libafl::observers::concolic::{
    serialization_format::{DEFAULT_ENV_NAME, DEFAULT_SIZE}, ConcolicObserver,
};
use libafl_bolts::{
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::tuple_list, AsSliceMut,
};
use libafl_qemu::{
    elf::EasyElf,
    modules::{usermode::SnapshotModule, SymQemuModule},
    sys::CPUArchState,
    Emulator, QemuExitError, QemuExitReason, Regs,
};

unsafe extern "C" {
    fn _libafl_sym_reset_state();
}

/// The `harness_snapshot.c` magic prefix that steers execution into `foo()`
/// (nested comparisons that are only solvable with symbolic reasoning).
const FOO_PREFIX: [u8; 4] = *b"QEMU";

// Provided by libSymRuntime.so (linked as a shared dependency): a single
// runtime instance serves both the SymCC shim inside libqemu-x86_64.so
// (_rsym_* consumers) and our per-execution trace control.
unsafe extern "C" {
    fn _libafl_concolic_end_trace();
    fn _libafl_concolic_begin_trace();
}

#[derive(Parser, Debug)]
#[command(name = "snapshot_runner")]
#[command(about = "Snapshot-based concolic execution smoke test (hybrid SymQEMU bridge)")]
struct Opt {
    /// Guest binary to run (built from harness_snapshot.c)
    #[arg(short, long, default_value = "../fuzzer/target_snapshot.out")]
    binary: String,

    /// Number of iterations after the initial (concrete) run
    #[arg(short, long, default_value = "3")]
    iterations: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = Opt::parse();
    assert!(
        std::path::Path::new(&opt.binary).exists(),
        "guest binary {:?} not found; build the fuzzer first (cargo build in ../fuzzer)",
        opt.binary
    );

    // The concolic shared memory this process (host of both the emulator and the
    // symbolic runtime) reads the trace from.
    let mut shmem_provider = StdShMemProvider::new()?;
    let mut concolic_shmem = shmem_provider.new_shmem(DEFAULT_SIZE)?;
    // SAFETY: the only place we set this env var; the rlib-linked runtime
    // attaches to it lazily on the first _rsym_* call.
    unsafe { concolic_shmem.write_to_env(DEFAULT_ENV_NAME)? };

    let mut qemu_args = vec!["qemu-x86_64".to_string()];
    if std::env::var_os("SNAPSHOT_TRACE_TCG").is_some() {
        qemu_args.push("-d".into());
        qemu_args.push("in_asm,op".into());
        qemu_args.push("-D".into());
        qemu_args.push("/tmp/opencode/guest_tcg_smoke.log".into());
    }
    qemu_args.push(opt.binary.clone());
    qemu_args.push("dummy_input.bin".to_string());

    let builder =
        Emulator::<(), _, _, (), libafl::inputs::BytesInput, (), _>::empty()
        .qemu_parameters(qemu_args)
        .modules(tuple_list!(
            SnapshotModule::new(),
            SymQemuModule::new(0, 4096)
        ));
    let mut emulator = builder.build()?;
    // Match the fuzzer's crash handling: guest faults return cleanly from
    // qemu.run() as QemuExitReason::Crash instead of killing the process;
    // the snapshot restore recovers the guest for the next iteration.
    emulator.set_target_crash_handling(&libafl_qemu::TargetSignalHandling::ReturnToHarness);

    let qemu = emulator.qemu();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
    let entry = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("LLVMFuzzerTestOneInput not found in guest binary");
    log::info!("entry LLVMFuzzerTestOneInput @ {entry:#x}");

    // === 1. Run normally until the entry point ===
    qemu.set_breakpoint(entry);
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            other => panic!("unexpected QEMU exit while running to entry: {other:?}"),
        }
    }

    // Save the COMPLETE CPU state while stopped at the entry breakpoint
    // (pre-first-instruction): every iteration is reset to exactly this
    // state. CPUArchState == CPUX86State: all GPRs, RIP, RFLAGS, segments
    // (incl. FS/GS bases), x87 FPU, XMM/YMM, MXCSR, lazy-flag internals.
    let cpu = qemu
        .current_cpu()
        .or_else(|| qemu.cpu_from_index(0))
        .expect("no QEMU CPU found");
    let saved_cpu: CPUArchState = cpu.save_state();

    let buffer: u64 = qemu.read_reg(Regs::Rdi).expect("read RDI").into();
    let size: u64 = qemu.read_reg(Regs::Rsi).expect("read RSI").into();
    let sp: u64 = qemu.read_reg(Regs::Sp).expect("read SP").into();

    // Capture the snapshot-time buffer content. The buffer page is never
    // written by guest code, so SnapshotModule's dirty-page tracking never
    // restores it; without this, bytes beyond the current input length leak
    // in from previous iterations (e.g. a crashing input's solution bytes
    // would make a later short input crash "impossibly").
    let mut snapshot_buffer = vec![0u8; size as usize];
    qemu.read_mem(buffer, &mut snapshot_buffer)
        .expect("read snapshot-time buffer");
    let mut ret_addr_buf = [0u8; 8];
    qemu.read_mem(sp, &mut ret_addr_buf).expect("read ret addr");
    let ret_addr = u64::from_le_bytes(ret_addr_buf);
    log::info!("buffer={buffer:#x} size={size} sp={sp:#x} ret_addr={ret_addr:#x}");

    // === 2. Capture the snapshot at the entry point ===
    {
        let modules = emulator.modules_mut();
        let snapshot = modules.get_mut::<SnapshotModule>().unwrap();
        snapshot.use_manual_reset();
        snapshot.snapshot(qemu);
        modules
            .get_mut::<SymQemuModule>()
            .unwrap()
            .set_buffer_addr(buffer);
    }
    log::info!("snapshot captured at {entry:#x}");

    // From now on, stop at the return address of LLVMFuzzerTestOneInput.
    qemu.remove_breakpoint(entry);
    qemu.set_breakpoint(ret_addr);

    let inputs: Vec<Vec<u8>> = vec![
        // prefix steers into foo(); inner conditions unsolved -> deep constraints
        [
            &FOO_PREFIX[..],
            &[0x11u8, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0] as &[u8],
        ]
        .concat(),
        // solution-ish input for the first conditions of foo()
        [
            &FOO_PREFIX[..],
            &[0u8, 0, 0, 0, 0x42, 0x13, 0x37, 0x10, 0x10, 0x10, 0xEF, 0] as &[u8],
        ]
        .concat(),
        // goes to bar()
        vec![0x00; 16],
        // short inputs: exercise the `size < 16` early return
        b"QEMU".to_vec(),
        vec![0x00; 4],
        // crash the guest (full solution chain -> NULL deref in foo()), then
        // keep tracing short inputs afterwards: regression test for the
        // stale-buffer-tail bug (buffer must be restored to snapshot state,
        // not keep the crash input's solution bytes at [4..])
        b"QEMUB\x13\x37\xe9\x14\x7f\x80AAAAAAA".to_vec(),
        vec![0x00; 4],
        b"QEMU".to_vec(),
    ];

    for (i, input) in inputs.iter().take(opt.iterations + 1).enumerate() {
        log::info!(
            "=== iteration {i}: input len={} {:02x?} ===",
            input.len(),
            input
        );

        // === 3a. restore the snapshot (RAM/mappings; opt-out for A/B tests) ===
        if std::env::var_os("SMOKE_NO_RESTORE").is_none() {
            emulator
                .modules_mut()
                .get_mut::<SnapshotModule>()
                .unwrap()
                .reset(qemu);
            // SAFETY: drop stale symbolic ids before re-marking.
            unsafe { _libafl_sym_reset_state() };
        } else {
            println!("[experiment] SNAPSHOT RESTORE SKIPPED this iteration");
        }

        // SnapshotModule::reset restores guest RAM, mappings, mprotect
        // states, brk and mmap layout — but NOT the CPU. Restore the
        // complete architectural CPU state captured at the entry
        // breakpoint so re-execution starts from a state identical to the
        // first run (any harness, any calling convention). LibAFL
        // breakpoints live outside the env struct, so the armed
        // return-address breakpoint survives the restore.
        cpu.restore_state(&saved_cpu);

        // Start a fresh trace (the previous iteration's trace was consumed).
        // SAFETY: runtime lives in this process.
        if i > 0 {
            unsafe { _libafl_concolic_begin_trace() };
        }

        // === 3b. write the input into the guest buffer ===
        // Restore the FULL buffer to snapshot-time content first, then
        // overlay the input (see snapshot_buffer comment above).
        let len = input.len().min(size as usize).min(4096);
        let mut guest_buffer = snapshot_buffer.clone();
        guest_buffer[..len].copy_from_slice(&input[..len]);
        qemu.write_mem(buffer, &guest_buffer)
            .expect("write input to guest buffer");

        // === 3c. mark the input-length prefix symbolic (g2h inside module) ===
        emulator
            .modules_mut()
            .get_mut::<SymQemuModule>()
            .unwrap()
            .mark_buffer_symbolic(qemu, len);

        // === 3d. resume execution until the return address ===
        let start = std::time::Instant::now();
        let exit = unsafe { qemu.run() };
        let elapsed = start.elapsed();
        let exit_kind = match exit {
            Ok(QemuExitReason::Breakpoint(_)) => "return",
            Ok(QemuExitReason::Crash) => "crash",
            Ok(QemuExitReason::Timeout) => "timeout",
            Err(QemuExitError::UnexpectedExit) => "unexpected-exit",
            other => panic!("unexpected QEMU exit: {other:?}"),
        };
        log::info!("exit: {exit_kind} after {elapsed:?}");

        // === 3e. finalize the trace and read it back ===
        // SAFETY: the runtime lives in this process; finish updates the length
        // header so the observer can read the trace of this execution.
        unsafe { _libafl_concolic_end_trace() };

        let observer = ConcolicObserver::new("concolic", concolic_shmem.as_slice_mut());
        let metadata = observer.create_metadata_from_current_map();
        let msgs = metadata.iter_messages().count();
        log::info!("trace: {msgs} symbolic expressions");
        assert!(
            msgs > 0,
            "concolic trace is empty: symbolic execution did not produce any expressions"
        );
    }

    println!("\nSMOKE TEST PASSED: snapshot + symbolic execution + trace retrieval all work");
    Ok(())
}
