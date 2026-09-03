//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! Simple concolic fuzzing example using SymQEMU.
use std::{
    env, fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use clap::{self, Parser};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{setup_restarting_mgr_std, EventConfig},
    executors::{
        command::CommandConfigurator, inprocess::InProcessExecutor, Executor, ExitKind,
        HasObservers, ShadowExecutor,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, ToTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator,
        token_mutations::I2SRandReplace,
    },
    observers::{
        concolic::{
            serialization_format::{DEFAULT_ENV_NAME, DEFAULT_SIZE},
            ConcolicObserver,
        },
        CanTrack, ObserversTuple, TimeObserver,
    },
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        ConcolicTracingStage, ShadowTracingStage, SimpleConcolicMutationalStage,
        StdMutationalStage, TracingStage,
    },
    state::{HasCorpus, HasExecutions, StdState},
    Error,
};
use libafl_bolts::{
    current_nanos,
    ownedref::OwnedSlice,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled, MatchName, RefIndexable},
    AsSlice, AsSliceMut,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Parser)]
struct Opt {
    /// This node should do concolic tracing + solving instead of traditional fuzzing
    #[arg(short, long)]
    concolic: bool,

    /// Use SymCC for concolic execution (default is SymQEMU)
    #[arg(long)]
    use_symcc: bool,

    /// Use snapshot-based in-process concolic execution (requires QEMU usermode)
    #[arg(long)]
    use_snapshot: bool,

    /// Use fork-server mode for faster SymQEMU concolic execution (reuses process)
    #[arg(long)]
    use_forkserver: bool,
}

pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    let opt = Opt::parse();
    let _ = fs::remove_file("cur_input");
    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
        &opt,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    corpus_dirs: &[PathBuf],
    objective_dir: PathBuf,
    broker_port: u16,
    opt: &Opt,
) -> Result<(), Error> {
    let concolic = opt.concolic;
    let use_symcc = opt.use_symcc;
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr_std(monitor, broker_port, EventConfig::from_name("default")) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {err}");
                }
            },
        };

    // Create an observation channel using the coverage map
    // We don't use the hitcounts (see the Cargo.toml, we use pcguard_edges)
    let edges_observer = unsafe { std_edges_map_observer("edges").track_indices() };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();
    //let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new("./tmp_corpus").unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    println!("We're a client, let's fuzz :)");

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = ShadowExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
        )?,
        tuple_list!(cmplog_observer),
    );

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, corpus_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {corpus_dirs:?}"));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Setup a tracing stage in which we log comparisons
    let tracing = ShadowTracingStage::new();

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    // Setup a basic mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mutational = StdMutationalStage::new(mutator);

    if concolic {
        // The shared memory for the concolic runtime to write its trace to
        let mut concolic_shmem = StdShMemProvider::new()
            .unwrap()
            .new_shmem(DEFAULT_SIZE)
            .unwrap();
        // # Safety
        // The only place we access this env from
        unsafe {
            concolic_shmem.write_to_env(DEFAULT_ENV_NAME).unwrap();
        }

        // The concolic observer observers the concolic shared memory map.
        let concolic_observer = ConcolicObserver::new("concolic", concolic_shmem.as_slice_mut());
        let concolic_ref = concolic_observer.handle();

        if opt.use_forkserver {
            println!("Using fork-server SymQEMU for concolic execution");

            let fs_executor = ForkServerSymQEMUExecutor::new(tuple_list!(concolic_observer))?;
            let mut stages = tuple_list!(
                ConcolicTracingStage::new(
                    TracingStage::new(fs_executor),
                    concolic_ref,
                ),
                SimpleConcolicMutationalStage::new(),
            );

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        } else if opt.use_snapshot {
            #[cfg(feature = "qemu-snapshot")]
            {
                println!("Using SymQEMU snapshot-based concolic execution (in-process)");
                println!("[snapshot-mode] NOTE: tracing iterations run the guest under the hybrid");
                println!("[snapshot-mode] QEMU and do NOT increase the broker's 'executions' counter;");
                println!("[snapshot-mode] edges only grow when Z3-generated mutations are evaluated");
                println!("[snapshot-mode] natively. 'edges: X/Y' means Y = distinct native edges");
                println!("[snapshot-mode] discovered so far (dynamic, not a fixed total).");

                let snapshot_executor =
                    SnapshotConcolicExecutor::new(tuple_list!(concolic_observer));
                let mut stages = tuple_list!(
                    ConcolicTracingStage::new(
                        TracingStage::new(snapshot_executor),
                        concolic_ref,
                    ),
                    SimpleConcolicMutationalStage::new(),
                );

                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
            }
            #[cfg(not(feature = "qemu-snapshot"))]
            {
                println!("ERROR: --use-snapshot requires building with the qemu-snapshot feature:");
                println!("  source ../snapshot_runner/env.sh && cargo build --release --features qemu-snapshot");
                return Err(Error::invalid_input(
                    "--use-snapshot requires the qemu-snapshot build feature",
                ));
            }
        } else if use_symcc {
            println!("Using SymCC for concolic execution");
            // The order of the stages matter!
            let mut stages = tuple_list!(
                // Create a concolic trace using SymCC (compile-time instrumentation)
                ConcolicTracingStage::new(
                    TracingStage::new(MyCommandConfiguratorSymCC::default().into_executor(
                        tuple_list!(concolic_observer),
                        None,
                        None
                    ),),
                    concolic_ref,
                ),
                // Use the concolic trace for z3-based solving
                SimpleConcolicMutationalStage::new(),
            );

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        } else {
            println!("Using SymQEMU for concolic execution");
            // The order of the stages matter!
            let mut stages = tuple_list!(
                // Create a concolic trace using SymQEMU (runtime instrumentation)
                ConcolicTracingStage::new(
                    TracingStage::new(MyCommandConfiguratorSymQEMU::default().into_executor(
                        tuple_list!(concolic_observer),
                        None,
                        None
                    ),),
                    concolic_ref,
                ),
                // Use the concolic trace for z3-based solving
                SimpleConcolicMutationalStage::new(),
            );

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        }
    } else {
        // The order of the stages matter!
        let mut stages = tuple_list!(tracing, i2s, mutational);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
    }

    // Never reached
    Ok(())
}

/// In-process snapshot-based concolic executor over the hybrid QEMU
/// (LibAFL bridge + SymQEMU symbolic TCG, see `qemu-hybrid/`).
///
/// On the first [`Executor::run_target`] call it starts the emulator on
/// `target_snapshot.out`, runs the guest normally until the
/// `LLVMFuzzerTestOneInput` breakpoint and captures a full snapshot
/// (CPU + RAM) there. Every subsequent call restores the snapshot, writes
/// the input into the guest input buffer, marks it symbolic via the SymCC
/// runtime and resumes execution until the harness returns. The concolic
/// trace lands in the shared memory observed by [`ConcolicObserver`].
#[cfg(feature = "qemu-snapshot")]
mod snapshot_concolic {
    use std::fs;

    use libafl::{
        executors::{Executor, ExitKind, HasObservers},
        inputs::{BytesInput, HasTargetBytes},
        observers::ObserversTuple,
        Error,
    };
    use libafl_bolts::{
        tuples::{tuple_list, MatchName, RefIndexable},
        AsSlice,
    };
    use libafl_qemu::{
        command::NopCommandManager,
        elf::EasyElf,
        modules::{usermode::SnapshotModule, SymQemuModule},
        sys::CPUArchState,
        Emulator, NopEmulatorDriver, NopSnapshotManager, Qemu, QemuExitError, QemuExitReason,
        Regs,
    };

    // Control hooks provided by libSymRuntime.so (linked via build.rs):
    // finalize the trace after each execution / begin a fresh one.
    unsafe extern "C" {
        fn _libafl_concolic_end_trace();
        fn _libafl_concolic_begin_trace();
    }

    // Provided by the hybrid shim (libSymCCRtShared.so): zero all symbolic
    // state (CPU env_exprs region + memory shadow pages).
    unsafe extern "C" {
        fn _libafl_sym_reset_state();
    }

    /// Size of the dummy input file used to boot the guest; the harness
    /// mallocs its input buffer from the file size, so this is also the
    /// maximum input length applied per execution.
    const GUEST_INPUT_FILE_SIZE: usize = 4096;

    struct Inner {
        emulator:
            Emulator<
                (),
                NopCommandManager,
                NopEmulatorDriver,
                (SnapshotModule, (SymQemuModule, ())),
                BytesInput,
                (),
                NopSnapshotManager,
            >,
        qemu: Qemu,
        /// Full architectural CPU state captured at the entry breakpoint.
        /// `CPUArchState` is the bindgen'd `CPUX86State`: all 16 GPRs, RIP,
        /// RFLAGS, segment registers (including FS/GS bases), GDT/IDT/LDT/TSS,
        /// CR/DR registers, x87 FPU stack + control/status, XMM/YMM state,
        /// MXCSR, MSRs and the TCG-internal lazy-flag fields. Neither
        /// `SnapshotModule::reset` nor anything else rewinds the CPU, so this
        /// state is restored before every execution. Saving the whole env
        /// (instead of rewriting individual argument registers) makes the
        /// reset correct for ANY harness: arbitrary calling conventions and
        /// argument registers, stack-passed arguments (restored with the
        /// stack RAM by the snapshot), SSE/AVX-using code, and functions
        /// that observe flags or callee-saved registers.
        saved_cpu: CPUArchState,
        buffer: u64,
        buffer_size: usize,
        /// Guest input-buffer content at snapshot time. The buffer page is
        /// only ever written host-side (write_mem), which does NOT mark it
        /// dirty in SnapshotModule's hook-based tracking - so reset() would
        /// leave bytes from PREVIOUS inputs in place ([len, buffer_size)
        /// tail). Restoring this copy first makes every iteration start
        /// from the exact snapshot-time buffer state.
        snapshot_buffer: Vec<u8>,
        #[allow(dead_code)]
        ret_addr: u64,
        traced_before: bool,
    }

    pub struct SnapshotConcolicExecutor<OT> {
        observers: OT,
        inner: Option<Inner>,
        traced_count: usize,
    }

    impl<OT> SnapshotConcolicExecutor<OT> {
        /// Content of the dummy input file. The guest main() only routes into
        /// foo() (our default snapshot entry) when the input starts with
        /// "QEMU", so the initial concrete run actually reaches the entry
        /// breakpoint.
        fn guest_input_file_content() -> Vec<u8> {
            let mut content = vec![0u8; GUEST_INPUT_FILE_SIZE];
            content[..4].copy_from_slice(b"QEMU");
            content
        }

        pub fn new(observers: OT) -> Self {
            Self {
                observers,
                inner: None,
                traced_count: 0,
            }
        }

        fn init_inner(&mut self) -> Result<(), Error> {
            // The guest main() reads argv[1] into a malloc'd buffer. Content
            // is irrelevant (overwritten per execution), only the size
            // determines the buffer allocation.
            eprintln!("[snapshot-executor] init: writing guest input file");
            fs::write("cur_input", Self::guest_input_file_content())?;

            // Guest binary for the snapshot flow (built by build.rs from
            // harness_snapshot.c; override with SNAPSHOT_TARGET_BIN).
            let guest_bin = std::env::var("SNAPSHOT_TARGET_BIN")
                .unwrap_or_else(|_| "./target_snapshot.out".to_string());
            let mut qemu_args = vec!["qemu-x86_64".to_string()];
            if std::env::var_os("SNAPSHOT_TRACE_TCG").is_some() {
                qemu_args.push("-d".into());
                qemu_args.push("in_asm,op".into());
                qemu_args.push("-D".into());
                qemu_args.push("/tmp/opencode/guest_tcg.log".into());
            }
            qemu_args.push(guest_bin);
            qemu_args.push("cur_input".to_string());

            eprintln!("[snapshot-executor] init: building emulator (QEMU init)");
            let builder = Emulator::<(), _, _, (), BytesInput, (), _>::empty()
                .qemu_parameters(qemu_args)
                .modules(tuple_list!(
                    SnapshotModule::new(),
                    SymQemuModule::new(0, GUEST_INPUT_FILE_SIZE)
                ));
            let mut emulator = builder.build()?;
            // Guest crashes (e.g. the harness's intended NULL deref once Z3
            // solves the full chain) return cleanly from qemu.run() as
            // QemuExitReason::Crash instead of killing the process; the
            // snapshot restore recovers the guest for the next iteration.
            emulator.set_target_crash_handling(&libafl_qemu::TargetSignalHandling::ReturnToHarness);

            eprintln!("[snapshot-executor] init: emulator built, resolving entry");
            let qemu = emulator.qemu();

            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
            // Snapshot entry point: symbol name, resolved against the guest
            // load base at runtime. Precedence: SNAPSHOT_TARGET_FUNCTION env
            // var > SNAPSHOT_DEFAULT_FUNCTION (set in build.rs) > fallback.
            let target_function = std::env::var("SNAPSHOT_TARGET_FUNCTION")
                .unwrap_or_else(|_| {
                    option_env!("SNAPSHOT_DEFAULT_FUNCTION")
                        .unwrap_or("LLVMFuzzerTestOneInput")
                        .to_string()
                });
            let entry = elf
                .resolve_symbol(&target_function, qemu.load_addr())
                .ok_or_else(|| {
                    Error::invalid_input(format!(
                        "{target_function} not found in {}",
                        qemu.binary_path()
                    ))
                })?;

            eprintln!("[snapshot-executor] init: running guest to entry breakpoint");
            // === run normally until the entry point ===
            qemu.set_breakpoint(entry);
            let exit = unsafe { qemu.run() };
            match exit {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(_)) => {
                    return Err(Error::invalid_input(format!(
                        "the guest exited before reaching the entry function '{target_function}' - \
                         the input file content does not route execution into it"
                    )))
                }
                other => {
                    return Err(Error::invalid_input(format!(
                        "unexpected QEMU exit while running to entry: {other:?}"
                    )))
                }
            }

            eprintln!("[snapshot-executor] init: reached entry, capturing CPU state");
            // Save the COMPLETE CPU state while stopped at the entry
            // breakpoint (pre-first-instruction): every iteration is reset
            // to exactly this state. Take it before any other register
            // access so nothing can perturb the snapshot.
            let cpu = qemu
                .current_cpu()
                .or_else(|| qemu.cpu_from_index(0))
                .ok_or_else(|| Error::invalid_input("no QEMU CPU found"))?;
            let saved_cpu = cpu.save_state();

            eprintln!("[snapshot-executor] init: reading regs");
            let buffer: u64 = qemu
                .read_reg(Regs::Rdi)
                .map_err(|e| Error::invalid_input(format!("failed to read RDI: {e:?}")))?
                .into();
            let sp: u64 = qemu
                .read_reg(Regs::Sp)
                .map_err(|e| Error::invalid_input(format!("failed to read SP: {e:?}")))?
                .into();
            let mut ret_addr_buf = [0u8; 8];
            qemu.read_mem(sp, &mut ret_addr_buf)
                .map_err(|e| Error::invalid_input(format!("failed to read return address: {e:?}")))?;
            let ret_addr = u64::from_le_bytes(ret_addr_buf);

            // The buffer size is NOT taken from RSI: at e.g. foo(data, ptr)
            // the second register holds the (NULL) ptr argument, not a size.
            // guest main() always mallocs exactly GUEST_INPUT_FILE_SIZE bytes
            // (the dummy file we wrote), so that is the allocated size.
            let buffer_size = GUEST_INPUT_FILE_SIZE;

            // Capture the snapshot-time buffer content. The buffer page is
            // never written by guest code, so SnapshotModule's dirty-page
            // tracking never restores it; without this, bytes beyond the
            // current input length leak in from previous iterations.
            let mut snapshot_buffer = vec![0u8; buffer_size];
            qemu.read_mem(buffer, &mut snapshot_buffer).map_err(|e| {
                Error::invalid_input(format!(
                    "failed to read the input buffer {buffer:#x} (size {buffer_size}) \
                     at entry function '{target_function}' (RDI={buffer:#x}): {e:?} - the \
                     snapshot entry must be a function whose first argument is the \
                     input data buffer; set SNAPSHOT_TARGET_FUNCTION accordingly"
                ))
            })?;

            eprintln!("[snapshot-executor] init: capturing snapshot");
            // === capture the snapshot at the entry point ===
            {
                let modules = emulator.modules_mut();
                let snapshot = modules
                    .get_mut::<SnapshotModule>()
                    .expect("SnapshotModule in tuple");
                snapshot.use_manual_reset();
                snapshot.snapshot(qemu);
                modules
                    .get_mut::<SymQemuModule>()
                    .expect("SymQemuModule in tuple")
                    .set_buffer_addr(buffer);
                modules
                    .get_mut::<SymQemuModule>()
                    .expect("SymQemuModule in tuple")
                    .set_buffer_size(buffer_size);
            }

            // From now on, stop at the return address of LLVMFuzzerTestOneInput.
            qemu.remove_breakpoint(entry);
            qemu.set_breakpoint(ret_addr);

            println!(
                "[snapshot-executor] entry {entry:#x}, buffer {buffer:#x} (size {buffer_size}), ret {ret_addr:#x}"
            );

            self.inner = Some(Inner {
                emulator,
                qemu,
                saved_cpu,
                buffer,
                buffer_size,
                snapshot_buffer,
                ret_addr,
                traced_before: false,
            });
            Ok(())
        }
    }

    impl<EM, OT, S, Z> Executor<EM, BytesInput, S, Z> for SnapshotConcolicExecutor<OT>
    where
        OT: MatchName + ObserversTuple<BytesInput, S>,
    {
        fn run_target(
            &mut self,
            _fuzzer: &mut Z,
            _state: &mut S,
            _mgr: &mut EM,
            input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            if self.inner.is_none() {
                self.init_inner()?;
            }
            let inner = self.inner.as_mut().expect("inner initialized");

            if inner.traced_before {
                // Finish of the previous trace already happened at the end of
                // the last run; start the fresh trace for this execution.
                // SAFETY: the runtime lives in this process (libSymRuntime.so).
                unsafe { _libafl_concolic_begin_trace() };
            }
            inner.traced_before = true;

            // === restore the snapshot ===
            inner
                .emulator
                .modules_mut()
                .get_mut::<SnapshotModule>()
                .expect("SnapshotModule in tuple")
                .reset(inner.qemu);

            // SnapshotModule::reset restores guest RAM, mappings, mprotect
            // states, brk and mmap layout — but NOT the CPU. Restore the
            // complete architectural CPU state captured at the entry
            // breakpoint: every GPR, RIP, RFLAGS, segment registers with
            // bases, x87 FPU, XMM/YMM, MXCSR and the lazy-flag internals.
            // This re-enters the target function from a state identical to
            // the first execution, for any harness and calling convention.
            // (LibAFL breakpoints live outside the env struct, so the armed
            // return-address breakpoint survives the restore.)
            inner
                .qemu
                .current_cpu()
                .or_else(|| inner.qemu.cpu_from_index(0))
                .ok_or_else(|| Error::invalid_input("no QEMU CPU found"))?
                .restore_state(&inner.saved_cpu);

            // SAFETY: shim export; drop stale symbolic ids (CPU env_exprs,
            // memory shadow) so this trace only references expressions
            // created during THIS execution. The translated blocks
            // themselves carry no persistent symbolic state, so no JIT
            // flush is needed.
            unsafe { _libafl_sym_reset_state() };

            // === write the input into the guest buffer ===
            // First restore the FULL buffer to its snapshot-time content:
            // SnapshotModule::reset never rewrites this page (it is only
            // ever written host-side, so it is never marked dirty), and
            // leaving stale bytes in [len, buffer_size) would let previous
            // inputs' data leak into this execution. Then overlay the input.
            let bytes = input.target_bytes();
            let buf = AsSlice::as_slice(&bytes);
            let len = buf.len().min(inner.buffer_size);
            let mut guest_buffer = inner.snapshot_buffer.clone();
            guest_buffer[..len].copy_from_slice(&buf[..len]);
            inner
                .qemu
                .write_mem(inner.buffer, &guest_buffer)
                .map_err(|e| Error::invalid_input(format!("failed to write guest input: {e:?}")))?;

            // === mark the (input-length prefix of the) buffer symbolic ===
            inner
                .emulator
                .modules_mut()
                .get_mut::<SymQemuModule>()
                .expect("SymQemuModule in tuple")
                .mark_buffer_symbolic(inner.qemu, len);

            // === resume execution until the harness returns ===
            let exit = unsafe { inner.qemu.run() };

            // === finalize the trace so the ConcolicObserver can read it ===
            // SAFETY: see above.
            unsafe { _libafl_concolic_end_trace() };

            self.traced_count += 1;
            if self.traced_count % 25 == 0 {
                // Tracing iterations are invisible in the broker stats
                // (executions/edges come from native mutation evaluation);
                // this line is the live "it is working" signal.
                println!(
                    "[snapshot-executor] traced {} inputs so far",
                    self.traced_count
                );
            }

            match exit {
                Ok(QemuExitReason::Breakpoint(_)) => Ok(ExitKind::Ok),
                Ok(QemuExitReason::Crash) => Ok(ExitKind::Crash),
                Ok(QemuExitReason::Timeout) => Ok(ExitKind::Timeout),
                Err(QemuExitError::UnexpectedExit) => Ok(ExitKind::Crash),
                other => Err(Error::invalid_input(format!(
                    "unexpected QEMU exit: {other:?}"
                ))),
            }
        }
    }

    impl<OT> HasObservers for SnapshotConcolicExecutor<OT> {
        type Observers = OT;

        fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
            RefIndexable::from(&self.observers)
        }

        fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
            RefIndexable::from(&mut self.observers)
        }
    }
}

#[cfg(feature = "qemu-snapshot")]
use snapshot_concolic::SnapshotConcolicExecutor;

#[derive(Default, Debug)]
pub struct MyCommandConfiguratorSymQEMU {
    timeout: Duration,
}

impl CommandConfigurator<Child> for MyCommandConfiguratorSymQEMU {
    fn spawn_child(&mut self, target_bytes: OwnedSlice<'_, u8>) -> Result<Child, Error> {
        fs::write("cur_input", target_bytes.as_slice())?;

        // Run the target through SymQEMU with rust_backend for dynamic concolic instrumentation
        // SymQEMU is now built with AFL++ fork's rust_backend, which properly integrates with LibAFL
        // The rust_backend C++ wrapper (libSymCCRtShared.so) translates _sym_* to _rsym_* calls
        // The actual implementation is in LibAFL's Rust runtime (libSymRuntime.so)
        
        // Get the shared memory env var from parent and pass it to child
        // LibAFL's Rust runtime uses SHARED_MEMORY_MESSAGES to find the shmem
        let shmem_env = env::var(DEFAULT_ENV_NAME)
            .expect("Concolic shared memory env var not set in parent process");

        Ok(Command::new("./qemu-x86_64")
            .arg("./target_main.out")
            .arg("cur_input")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Use FileInput mode: SymQEMU will mark the contents of this file as symbolic
            // MemoryInput mode would require explicit _sym_make_symbolic() calls in the target
            .env("SYMCC_INPUT_FILE", "cur_input")
            // NOTE: LD_LIBRARY_PATH not needed:
            // - qemu-x86_64 finds libSymCCRtShared.so in current directory
            // - libSymCCRtShared.so finds libSymRuntime.so via RPATH (hardcoded at build time)
            //.env("LD_LIBRARY_PATH", ".:/home/device-admin/LibAFL/fuzzers/structure_aware/libfuzzer_simple_concolic/runtime/target/release")
            // NOTE: DEFAULT_ENV_NAME also inherited automatically from parent, but explicit for clarity
            .env(DEFAULT_ENV_NAME, &shmem_env)
            .spawn()
            .expect("failed to start process"))
    }

    fn exec_timeout(&self) -> Duration {
        self.timeout
    }

    fn exec_timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
}

#[derive(Default, Debug)]
pub struct MyCommandConfiguratorSymCC {
    timeout: Duration,
}

impl CommandConfigurator<Child> for MyCommandConfiguratorSymCC {
    fn spawn_child(&mut self, target_bytes: OwnedSlice<'_, u8>) -> Result<Child, Error> {
        fs::write("cur_input", target_bytes.as_slice())?;

        let shmem_env = env::var(DEFAULT_ENV_NAME)
            .expect("Concolic shared memory env var not set in parent process");

        Ok(Command::new("./target_symcc.out")
            .arg("cur_input")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("SYMCC_INPUT_FILE", "cur_input")
            .env(DEFAULT_ENV_NAME, &shmem_env)
            .spawn()
            .expect("failed to start process"))
    }

    fn exec_timeout(&self) -> Duration {
        self.timeout
    }

    fn exec_timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
}

fn wait_for_stop(child: &mut Child) -> Result<(), Error> {
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    if ret < 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "waitpid on fork-server failed").into());
    }
    if libc::WIFSTOPPED(status) {
        Ok(())
    } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "fork-server process exited unexpectedly").into())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "unexpected waitpid status").into())
    }
}

#[derive(Debug)]
pub struct ForkServerSymQEMUExecutor<OT> {
    child: Child,
    observers: OT,
}

impl<OT> ForkServerSymQEMUExecutor<OT> {
    pub fn new(observers: OT) -> Result<Self, Error> {
        let shmem_env =
            env::var(DEFAULT_ENV_NAME).expect("Concolic shmem env var not set in parent");

        let mut child = Command::new("./qemu-x86_64")
            .arg("./target_forkserver.out")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("SYMCC_INPUT_FILE", "cur_input")
            .env(DEFAULT_ENV_NAME, &shmem_env)
            .spawn()?;

        eprintln!("[forkserver] waiting for initial SIGSTOP...");
        wait_for_stop(&mut child)?;
        eprintln!("[forkserver] fork-server ready");

        Ok(Self { child, observers })
    }
}

impl<OT> Drop for ForkServerSymQEMUExecutor<OT> {
    fn drop(&mut self) {
        eprintln!("[forkserver] killing fork-server process");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for ForkServerSymQEMUExecutor<OT>
where
    OT: MatchName + ObserversTuple<I, S>,
    S: HasExecutions,
    Z: ToTargetBytes<I>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let bytes = fuzzer.to_target_bytes(input);
        fs::write("cur_input", bytes.as_slice())?;

        self.observers_mut().pre_exec_child_all(state, input)?;

        let pid = self.child.id() as libc::pid_t;
        let ret = unsafe { libc::kill(pid, libc::SIGCONT) };
        if ret < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "SIGCONT to fork-server failed").into());
        }

        wait_for_stop(&mut self.child)?;

        let exit_kind = ExitKind::Ok;
        self.observers_mut().post_exec_child_all(state, input, &exit_kind)?;
        Ok(exit_kind)
    }
}

impl<OT> HasObservers for ForkServerSymQEMUExecutor<OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
