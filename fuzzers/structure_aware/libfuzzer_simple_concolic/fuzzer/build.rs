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

fn use_prebuilt_symqemu(_runtime_lib_dir: &Path) -> PathBuf {
    // Use the pre-built SymQEMU from /home/device-admin/symqemu
    // This is the forked version with integrated AFL++ runtime (rust_backend)
    let symqemu_home = PathBuf::from("/home/device-admin/symqemu");
    let symqemu_build = symqemu_home.join("build");
    
    println!("Using pre-built SymQEMU from: {:?}", symqemu_home);
    
    if !symqemu_build.exists() {
        println!("cargo:warning=SymQEMU build directory not found at {:?}", symqemu_build);
        println!("cargo:warning=Please build SymQEMU first: cd /home/device-admin/symqemu && meson configure build -Dsymcc_rt_backend=rust && ninja -C build");
        exit(1);
    }
    
    let qemu_bin = symqemu_build.join("qemu-x86_64");
    
    if !qemu_bin.exists() {
        println!("cargo:warning=qemu-x86_64 binary not found at {:?}", qemu_bin);
        println!("cargo:warning=Please build SymQEMU first: cd /home/device-admin/symqemu && ninja -C build");
        exit(1);
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
        println!("cargo:warning=Rebuild with: cd /home/device-admin/symqemu && meson configure build -Dsymcc_rt_backend=rust && ninja -C build");
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

    // === 3. Build the LibAFL SymCC runtime (Rust implementation) ===
    println!("Building LibAFL Rust runtime...");
    std::process::Command::new("cargo")
        .current_dir(&runtime_dir)
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--release")
        .status()
        .expect("Failed to build runtime");

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

    // === 4. Clone AFL++ SymCC fork (has rust_backend) ===
    let symcc_src_dir = out_path.join("aflpp_symcc_src");
    if !symcc_src_dir.exists() {
        println!("Cloning AFL++ SymCC fork...");
        symcc_libafl::clone_symcc(&symcc_src_dir);
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

    // === 6. Use pre-built SymQEMU with rust_backend ===
    let symqemu_dir = use_prebuilt_symqemu(&runtime_dir);
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
        println!("cargo:warning=Building harness_symcc.c with SymCC failed");
        let mut stdout = stdout();
        stdout
            .write_all(&output.stderr)
            .expect("failed to write cc error message to stdout");
        exit(1);
    }

    println!("Build completed successfully!");
    println!("- target_main.out: Plain binary for SymQEMU");
    println!("- target_symcc.out: SymCC instrumented binary");
    println!("- qemu-x86_64: SymQEMU with LibAFL rust_backend");
    println!("- libSymRuntime.so: LibAFL Rust runtime");
}
