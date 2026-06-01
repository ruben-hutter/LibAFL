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
    inputs::{BytesInput, HasTargetBytes},
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
        } else if use_snapshot {
            println!("Using SymQEMU snapshot-based concolic execution (in-process)");

            let configurator = MyCommandConfiguratorSymQemuSnapshot::new();
            let mut stages = tuple_list!(
                ConcolicTracingStage::new(
                    TracingStage::new(configurator.into_executor(
                        tuple_list!(concolic_observer),
                        None,
                        None
                    ),),
                    concolic_ref,
                ),
                SimpleConcolicMutationalStage::new(),
            );

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        } else if use_symcc {
            println!("Using SymCC for concolic execution");
            // The order of the stages matter!
            let mut stages = tuple_list!(
                // Create a concolic trace using SymCC (compile-time instrumentation)
                ConcolicTracingStage::new(
                    TracingStage::new(MyCommandConfiguratorSymCC.into_executor(
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
                    TracingStage::new(MyCommandConfiguratorSymQEMU.into_executor(
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

#[derive(Default, Debug)]
pub struct MyCommandConfiguratorSymQemuSnapshot {
    target_function: String,
}

impl MyCommandConfiguratorSymQemuSnapshot {
    pub fn new() -> Self {
        Self {
            target_function: env::var("SNAPSHOT_TARGET_FUNCTION")
                .unwrap_or_else(|_| "LLVMFuzzerTestOneInput".to_string()),
        }
    }
}

impl CommandConfigurator<Child> for MyCommandConfiguratorSymQemuSnapshot {
    fn spawn_child(&mut self, target_bytes: OwnedSlice<'_, u8>) -> Result<Child, Error> {
        fs::write("cur_input", target_bytes.as_slice())?;

        let shmem_env = env::var(DEFAULT_ENV_NAME)
            .expect("Concolic shared memory env var not set in parent process");

        Ok(Command::new("./qemu-x86_64")
            .arg("./target_main.out")
            .arg("cur_input")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("SYMCC_INPUT_FILE", "cur_input")
            .env(DEFAULT_ENV_NAME, &shmem_env)
            .env("SYMCC_ENABLE_SNAPSHOT", "1")
            .env("SYMCC_SNAPSHOT_TARGET_FUNCTION", &self.target_function)
            .spawn()
            .expect("failed to start SymQEMU snapshot process"))
    }

    fn exec_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn exec_timeout_mut(&mut self) -> &mut Duration {
        static mut TIMEOUT: Duration = Duration::from_secs(5);
        unsafe { &mut TIMEOUT }
    }
}

#[derive(Default, Debug)]
pub struct MyCommandConfiguratorSymQEMU;

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
        Duration::from_secs(5)
    }

    fn exec_timeout_mut(&mut self) -> &mut Duration {
        static mut TIMEOUT: Duration = Duration::from_secs(5);
        unsafe { &mut TIMEOUT }
    }
}

#[derive(Default, Debug)]
pub struct MyCommandConfiguratorSymCC;

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
        Duration::from_secs(5)
    }

    fn exec_timeout_mut(&mut self) -> &mut Duration {
        static mut TIMEOUT: Duration = Duration::from_secs(5);
        unsafe { &mut TIMEOUT }
    }
}

fn wait_for_stop(child: &mut Child) -> Result<(), Error> {
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    if ret < 0 {
        return Err(Error::from("waitpid on fork-server failed"));
    }
    if libc::WIFSTOPPED(status) {
        Ok(())
    } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
        Err(Error::from("fork-server process exited unexpectedly"))
    } else {
        Err(Error::from("unexpected waitpid status"))
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
            return Err(Error::from("SIGCONT to fork-server failed"));
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
