// build.rs - Simplified version using AFL++ SymCC fork

use std::{
    env,
    io::{stdout, Write},
    path::{Path, PathBuf},
    process::exit,
};

use which::which;

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        println!("Checking for build tool {tool}...");

        if let Ok(path) = which(tool) {
            println!("Found build tool {}", path.to_str().unwrap());
        } else {
            println!("ERROR: missing build tool {tool}");
            exit(1);
        };
    }
}

fn build_aflpp_symcc_runtime(symcc_src_path: &Path) -> PathBuf {
    println!("Building AFL++ SymCC runtime with rust_backend...");
    
    // Use cmake to build the runtime with RUST_BACKEND=ON
    // This is the canonical way LibAFL builds it
    let runtime_build = cmake::Config::new(symcc_src_path.join("runtime"))
        .define("RUST_BACKEND", "ON")
        .define("Z3_TRUST_SYSTEM_VERSION", "ON")
        .cxxflag("-Wno-error=deprecated-declarations")
        .build();
    
    runtime_build.join("lib")
}

fn get_or_build_symqemu(out_path: &Path, runtime_lib_dir: &Path) -> PathBuf {
    // Check if SYMQEMU_DIR environment variable is set
    // Otherwise, use a cached version in the build output directory
    let symqemu_home = if let Ok(symqemu_dir) = env::var("SYMQEMU_DIR") {
        println!("Using SymQEMU from SYMQEMU_DIR: {}", symqemu_dir);
        let path = PathBuf::from(symqemu_dir);
        if !path.exists() {
            println!("cargo:warning=SYMQEMU_DIR points to non-existent directory: {:?}", path);
            exit(1);
        }
        path
    } else {
        let default_dir = out_path.join("symqemu");

        // Reuse a previously cloned+built standalone SymQEMU from an older
        // build-script out dir if present (cloning + first build is slow).
        if !default_dir.exists() {
            if let Some(siblings) = out_path.parent().and_then(|p| p.read_dir().ok()) {
                for entry in siblings.flatten() {
                    let cand = entry.path().join("out/symqemu");
                    if cand.join("build/qemu-x86_64").exists() {
                        println!(
                            "Reusing cached standalone SymQEMU from {} ...",
                            cand.display()
                        );
                        std::fs::create_dir_all(&default_dir).expect("failed to create dir");
                        let status = std::process::Command::new("cp")
                            .args(["-r"])
                            .arg(cand.join("."))
                            .arg(&default_dir)
                            .status()
                            .expect("failed to copy cached SymQEMU");
                        assert!(status.success(), "copying cached SymQEMU failed");
                        // Make the copied binary look fresh so the mtime
                        // comparison below does not trigger a rebuild.
                        let _ = std::process::Command::new("touch")
                            .arg(default_dir.join("build").join("qemu-x86_64"));
                        break;
                    }
                }
            }
        }

        // Clone SymQEMU if it doesn't exist
        if !default_dir.exists() {
            println!("SymQEMU not found, cloning from GitHub...");
            println!("This is a one-time setup and may take a few minutes...");
            symqemu_libafl::clone_symqemu(&default_dir);
        } else {
            println!("Using cached SymQEMU from: {:?}", default_dir);
        }

        default_dir
    };

    let symqemu_build = symqemu_home.join("build");
    let qemu_bin = symqemu_build.join("qemu-x86_64");

    // Build SymQEMU if not already built or if runtime was rebuilt
    let runtime_lib = runtime_lib_dir.join("target/release/libSymRuntime.so");
    let needs_rebuild = !qemu_bin.exists()
        || (runtime_lib.exists() && qemu_bin.metadata().unwrap().modified().unwrap()
            < runtime_lib.metadata().unwrap().modified().unwrap());

    if needs_rebuild {
        if !qemu_bin.exists() {
            println!("Building SymQEMU with rust_backend...");
            println!("This may take several minutes on first build...");
        } else {
            println!("Runtime was rebuilt, rebuilding SymQEMU...");
        }
        let _ = symqemu_libafl::build_symqemu(&symqemu_home);
    } else {
        println!("Using existing SymQEMU build at: {:?}", symqemu_build);
    }

    // Verify it's built with rust_backend by checking linked libraries
    let ldd_output = std::process::Command::new("ldd")
        .arg(&qemu_bin)
        .output()
        .expect("Failed to run ldd");

    let ldd_str = String::from_utf8_lossy(&ldd_output.stdout);

    // SymQEMU links to libSymCCRtShared.so (C++ wrapper), which then calls the Rust runtime
    if ldd_str.contains("libSymCCRtShared.so") {
        println!("✓ qemu-x86_64 is linked with LibAFL rust_backend (via libSymCCRtShared.so)");
    } else {
        println!("cargo:warning=qemu-x86_64 exists but doesn't link to libSymCCRtShared.so");
        println!("cargo:warning=It may be using the qsym backend instead of rust_backend");
        println!("cargo:warning=Rebuilding with rust_backend...");
        // Rebuild with correct backend
        let _ = symqemu_libafl::build_symqemu(&symqemu_home);
    }

    symqemu_build
}

fn main() {
    // This build script compiles three versions of the harness:
    // 1. harness.c - with sanitizer coverage for fuzzing
    // 2. harness_main.c - for SymQEMU runtime instrumentation
    // 3. harness_symcc.c - with SymCC compile-time instrumentation
    // All versions use -O0 to prevent compiler optimizations from removing bugs

    if !cfg!(target_os = "linux") {
        println!("cargo:warning=Only linux host is supported for now.");
        exit(0);
    }

    let out_path = PathBuf::from(&env::var_os("OUT_DIR").unwrap());
    let runtime_dir = std::env::current_dir().unwrap().join("..").join("runtime");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=harness.c");
    println!("cargo:rerun-if-changed=harness_main.c");
    println!("cargo:rerun-if-changed=harness_symcc.c");
    println!("cargo:rerun-if-changed=harness_forkserver.c");
    println!("cargo:rerun-if-changed=harness_snapshot.c");

    build_dep_check(&["clang", "clang++", "cmake", "meson", "ninja", "pkg-config", "git"]);

    // Set CC/CXX to clang once
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    // === 1. Build harness.c with clang and sanitizer coverage for fuzzing ===
    cc::Build::new()
        .flag("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        .flag("-Wno-sign-compare")
        .flag("-Wunused-but-set-variable")
        .flag("-O0")
        .file("./harness.c")
        .compile("harness");

    println!(
        "cargo:rustc-link-search=native={}",
        &out_path.to_string_lossy()
    );

    // === 2. Build harness_main.c with plain clang for SymQEMU runtime instrumentation ===
    cc::Build::new()
        .flag("-Wno-sign-compare")
        .flag("-Wunused-but-set-variable")
        .flag("-O0")
        .cargo_metadata(false)
        .get_compiler()
        .to_command()
        .arg("./harness_main.c")
        .args(["-o", "target_main.out"])
        .arg("-lm")
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                println!("cargo:warning=Building harness_main.c failed");
                stdout().write_all(&output.stderr).ok();
                exit(1);
            }
        })
        .expect("failed to compile harness_main.c");

    // === 2b. Build harness_forkserver.c for SymQEMU fork-server mode ===
    cc::Build::new()
        .flag("-Wno-sign-compare")
        .flag("-Wunused-but-set-variable")
        .flag("-O0")
        .cargo_metadata(false)
        .get_compiler()
        .to_command()
        .arg("./harness_forkserver.c")
        .args(["-o", "target_forkserver.out"])
        .arg("-lm")
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                println!("cargo:warning=Building harness_forkserver.c failed");
                stdout().write_all(&output.stderr).ok();
                exit(1);
            }
        })
        .expect("failed to compile harness_forkserver.c");

    // === 2c. Build harness_snapshot.c for SymQEMU snapshot mode ===
    cc::Build::new()
        .flag("-Wno-sign-compare")
        .flag("-Wunused-but-set-variable")
        .flag("-O0")
        .cargo_metadata(false)
        .get_compiler()
        .to_command()
        .arg("./harness_snapshot.c")
        .args(["-o", "target_snapshot.out"])
        .arg("-lm")
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                println!("cargo:warning=Building harness_snapshot.c failed");
                stdout().write_all(&output.stderr).ok();
                exit(1);
            }
        })
        .expect("failed to compile harness_snapshot.c");

    // === 3. Build the LibAFL SymCC runtime (Rust implementation) ===
    println!("Building LibAFL Rust runtime...");
    let mut runtime_build = std::process::Command::new("cargo");
    runtime_build
        .current_dir(&runtime_dir)
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--release");
    if std::env::var_os("CARGO_FEATURE_QEMU_SNAPSHOT").is_some() {
        // The hybrid QEMU already links the C++ _sym_* shim. Exporting the
        // same wrappers from libSymRuntime.so would create a second provider
        // and split trace control from the runtime receiving _rsym_* calls.
        runtime_build.arg("--no-default-features");
    }
    let status = runtime_build.status().expect("Failed to build runtime");
    if !status.success() {
        panic!("Building libSymRuntime.so failed");
    }
    // Rerun this build script (and thus rebuild the runtime) when its sources
    // change - otherwise libSymRuntime.so silently goes stale.
    println!(
        "cargo:rerun-if-changed={}",
        runtime_dir.join("src").join("lib.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        runtime_dir.join("Cargo.toml").display()
    );

    // Copy libSymRuntime.so to runtime directory for easier access
    std::fs::copy(
        runtime_dir
            .join("target")
            .join("release")
            .join("libSymRuntime.so"),
        runtime_dir.join("libSymRuntime.so"),
    )
    .expect("Failed to copy libSymRuntime.so");

    if !runtime_dir.join("libSymRuntime.so").exists() {
        println!("cargo:warning=Runtime not found. Build it first.");
        exit(1);
    }

    // The standalone SymQEMU/SymCC machinery below is only needed for the
    // spawn-per-execution modes (separate/symcc/forkserver). The in-process
    // qemu-snapshot mode uses the hybrid QEMU tree instead (linked at the
    // end of this script) and skips these steps entirely.
    if std::env::var_os("CARGO_FEATURE_QEMU_SNAPSHOT").is_none() {
    // === 4. Clone AFL++ SymCC fork (has rust_backend) ===
    let symcc_src_dir = out_path.join("aflpp_symcc_src");
    if !symcc_src_dir.exists() {
        // The AFLplusplus/symcc repository was removed from GitHub, so a
        // fresh clone fails. Reuse a previously cloned copy from the
        // symcc_runtime build cache instead, and only clone as last resort.
        let mut cached = None;
        let runtime_build_dir = runtime_dir.join("target/release/build");
        if let Ok(entries) = std::fs::read_dir(&runtime_build_dir) {
            for entry in entries.flatten() {
                let cand = entry.path().join("out/libafl_symcc_src");
                if cand.join("runtime").exists() {
                    cached = Some(cand);
                    break;
                }
            }
        }
        if let Some(cached) = cached {
            println!(
                "Copying cached symcc sources from {} ...",
                cached.display()
            );
            std::fs::create_dir_all(&symcc_src_dir).expect("failed to create symcc src dir");
            let status = std::process::Command::new("cp")
                .args(["-r"])
                .arg(&cached)
                .arg(".")
                .current_dir(&out_path)
                .status()
                .expect("failed to copy cached symcc sources");
            assert!(status.success(), "copying cached symcc sources failed");
            // The cached copy's build/ directory references the old out dir;
            // remove it so symcc_libafl reconfigures fresh.
            let _ = std::fs::remove_dir_all(symcc_src_dir.join("build"));
        } else {
            println!("Cloning AFL++ SymCC fork...");
            symcc_libafl::clone_symcc(&symcc_src_dir);
        }
    }

    // === 5. Build AFL++ SymCC runtime with rust_backend ===
    // This builds the C++ wrapper that translates _sym_* to _rsym_* calls
    // and links it with our Rust runtime
    let aflpp_runtime_lib = build_aflpp_symcc_runtime(&symcc_src_dir);
    println!("AFL++ SymCC runtime built at: {:?}", aflpp_runtime_lib);

    // Copy the built runtime library to our runtime directory
    // The C++ runtime (libSymRuntime.a) contains the wrapper that calls into our Rust runtime
    let symruntime_static = aflpp_runtime_lib.join("libSymRuntime.a");
    if symruntime_static.exists() {
        std::fs::copy(&symruntime_static, runtime_dir.join("libSymRuntime.a"))
            .expect("Failed to copy libSymRuntime.a");
        println!("Copied AFL++ SymCC runtime wrapper to runtime dir");
    } else {
        println!("cargo:warning=AFL++ SymCC runtime not found at {:?}", symruntime_static);
    }

    // === 6. Get or build SymQEMU with rust_backend ===
    let symqemu_dir = get_or_build_symqemu(&out_path, &runtime_dir);
    let qemu_bin = symqemu_dir.join("qemu-x86_64");

    // Copy the binary to current directory
    std::fs::copy(&qemu_bin, "qemu-x86_64")
        .expect("Failed to copy qemu-x86_64");
    println!("Copied qemu-x86_64 (with rust_backend) to current directory");

    // Copy libSymCCRtShared.so (C++ wrapper that qemu links to)
    let symcc_rt_shared = symqemu_dir.join("subprojects/symcc-rt/libSymCCRtShared.so");
    std::fs::copy(&symcc_rt_shared, "libSymCCRtShared.so")
        .expect("Failed to copy libSymCCRtShared.so");
    println!("Copied libSymCCRtShared.so (C++ wrapper) to current directory");

    // Note: We don't copy libSymRuntime.so because libSymCCRtShared.so has a hardcoded
    // RPATH to runtime/target/release/libSymRuntime.so, so it finds it automatically

    // === 7. Build SymCC compiler ===
    let symcc_dir = symcc_libafl::build_symcc(&symcc_src_dir);
    let symcc_bin = symcc_dir.join("symcc");
    println!("SymCC compiler built at: {:?}", symcc_bin);

    // Compile harness_symcc.c with SymCC
    let output = std::process::Command::new(&symcc_bin)
        .env("SYMCC_RUNTIME_DIR", &runtime_dir)
        .arg("-Wno-sign-compare")
        .arg("-Wunused-but-set-variable")
        .arg("-O0")
        .arg("./harness_symcc.c")
        .args(["-o", "target_symcc.out"])
        .arg("-lm")
        .output()
        .expect("failed to execute symcc");

    if !output.status.success() {
        println!("cargo:warning=Building harness_symcc.c with SymCC failed (non-fatal)");
    }
    } // end of standalone-mode build steps

    // === 5. In-process snapshot mode: link the SymCC runtime + C++ shim ===
    // The hybrid libqemu-x86_64.so (via libafl_qemu) references _rsym_*/_sym_*
    // that must resolve inside this process. Link the single shared runtime
    // instance and the C++ shim directly, with absolute rpaths baked in.
    if std::env::var_os("CARGO_FEATURE_QEMU_SNAPSHOT").is_some() {
        let base = std::env::current_dir().unwrap();
        let runtime_dir = base
            .join("..")
            .join("runtime")
            .join("target")
            .join("release")
            .canonicalize()
            .expect("runtime not built: run `cargo build --release` in ../runtime first");
        let shim_dir = base
            .join("..")
            .join("qemu-hybrid")
            .join("build")
            .join("subprojects")
            .join("symcc-rt")
            .canonicalize()
            .expect("qemu-hybrid not built (expected at ../qemu-hybrid)");
        let qemu_dir = base
            .join("..")
            .join("qemu-hybrid")
            .join("build")
            .canonicalize()
            .expect("qemu-hybrid not built (expected at ../qemu-hybrid)");

        println!("cargo:rustc-link-search=native={}", runtime_dir.display());
        println!("cargo:rustc-link-lib=dylib=SymRuntime");
        println!("cargo:rustc-link-search=native={}", shim_dir.display());
        println!("cargo:rustc-link-lib=dylib=SymCCRtShared");
        for dir in [&runtime_dir, &shim_dir, &qemu_dir] {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
        // Build libafl_qemu against the hybrid tree (must not fall back to
        // cloning the upstream bridge).
        if std::env::var_os("LIBAFL_QEMU_DIR").is_none() {
            panic!("qemu-snapshot feature requires LIBAFL_QEMU_DIR pointing at the hybrid QEMU tree (see snapshot_runner/env.sh)");
        }
        // Default snapshot entry function (runtime override:
        // SNAPSHOT_TARGET_FUNCTION env var). Must be a function whose first
        // argument is the input data buffer (libFuzzer convention).
        println!("cargo:rustc-env=SNAPSHOT_DEFAULT_FUNCTION=LLVMFuzzerTestOneInput");
    }

    println!("Build completed successfully!");
    println!("- target_main.out: Plain binary for SymQEMU");
    println!("- target_forkserver.out: Fork-server binary for SymQEMU fork-server mode");
    println!("- target_symcc.out: SymCC instrumented binary");
    println!("- qemu-x86_64: SymQEMU with LibAFL rust_backend");
    println!("- libSymRuntime.so: LibAFL Rust runtime");
}
