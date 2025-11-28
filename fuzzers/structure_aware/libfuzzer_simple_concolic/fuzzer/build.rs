// build.rs

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

fn clone_and_build_symqemu(out_path: &Path, runtime_dir: &Path) -> PathBuf {
    let repo_dir = out_path.join("symqemu_src");

    if !repo_dir.exists() {
        println!("Cloning SymQEMU...");
        std::process::Command::new("git")
            .args(["clone", "https://github.com/eurecom-s3/symqemu.git"])
            .arg(&repo_dir)
            .status()
            .expect("Failed to clone SymQEMU");
    }

    println!("Updating SymQEMU submodules...");
    let submodule_status = std::process::Command::new("git")
        .current_dir(&repo_dir)
        .args([
            "submodule",
            "update",
            "--init",
            "--recursive",
            "subprojects/symcc-rt",
        ])
        .status()
        .expect("Failed to update SymQEMU submodules");

    if !submodule_status.success() {
        println!("cargo:warning=Failed to initialize SymQEMU submodules");
        exit(1);
    }

    let symqemu_build = repo_dir.join("build");

    // Check if already built
    if !symqemu_build.join("qemu-x86_64").exists() {
        println!("Building SymQEMU (this may take a while)...");

        let configure_status = std::process::Command::new("./configure")
            .current_dir(&repo_dir)
            .args([
                "--target-list=x86_64-linux-user",
                "--audio-drv-list=",
                "--disable-gtk",
                "--disable-vte",
                "--disable-opengl",
                "--disable-virglrenderer",
                "--disable-sdl",
                "--disable-werror",
            ])
            .status()
            .expect("Failed to configure SymQEMU");

        if !configure_status.success() {
            println!("cargo:warning=SymQEMU configure step failed");
            exit(1);
        }

        let build_status = std::process::Command::new("ninja")
            .current_dir(&repo_dir)
            .args(["-C", "build", "qemu-x86_64"])
            .status()
            .expect("Failed to build SymQEMU");

        if !build_status.success() {
            println!("cargo:warning=SymQEMU build step failed");
            exit(1);
        }
    }

    // Use LibAFL's custom runtime instead of SymQEMU's built-in standard runtime
    // This ensures SymQEMU communicates with LibAFL via shared memory
    let runtime_src = runtime_dir.join("libSymRuntime.so");
    if runtime_src.exists() {
        if let Err(err) = std::fs::copy(&runtime_src, "libSymCCRtShared.so") {
            println!(
                "cargo:warning=Failed to copy LibAFL SymCC runtime library: {}",
                err
            );
        }
    } else {
        println!("cargo:warning=LibAFL SymCC runtime not found. Build the runtime first.");
        exit(1);
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

    build_dep_check(&["clang", "clang++", "meson", "ninja", "pkg-config", "git"]);

    // Set CC/CXX to clang once - used by cc::Build for harness.c and harness_main.c
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    // === 1. Build harness.c with clang and sanitizer coverage for fuzzing ===
    cc::Build::new()
        .flag("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        .flag("-Wno-sign-compare")
        .flag("-Wunused-but-set-variable")
        .flag("-O0")
        .flag("-g")
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
        .flag("-g")
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

    // === 3. Build the LibAFL SymCC runtime ===
    std::process::Command::new("cargo")
        .current_dir(&runtime_dir)
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--release")
        .status()
        .expect("Failed to build runtime");

    std::fs::copy(
        runtime_dir
            .join("target")
            .join("release")
            .join("libSymRuntime.so"),
        runtime_dir.join("libSymRuntime.so"),
    )
    .unwrap();

    if !runtime_dir.join("libSymRuntime.so").exists() {
        println!("cargo:warning=Runtime not found. Build it first.");
        exit(1);
    }

    // === 4. Build SymQEMU ===
    let symqemu_dir = clone_and_build_symqemu(&out_path, &runtime_dir);
    let symqemu_bin = symqemu_dir.join("qemu-x86_64");
    if symqemu_bin.exists() {
        std::fs::copy(&symqemu_bin, "qemu-x86_64").expect("Failed to copy SymQEMU binary");
    } else {
        println!("cargo:warning=SymQEMU binary not found after build");
        exit(1);
    }

    // === 5. Build SymCC and harness_symcc.c ===
    let symcc_dir = clone_and_build_symcc(&out_path);
    let symcc_bin = symcc_dir.join("symcc");

    // Use SymCC directly without modifying CC/CXX environment variables
    let output = std::process::Command::new(&symcc_bin)
        .env("SYMCC_RUNTIME_DIR", &runtime_dir)
        .arg("-Wno-sign-compare")
        .arg("-Wunused-but-set-variable")
        .arg("-O0")
        .arg("-g")
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
}

fn clone_and_build_symcc(out_path: &Path) -> PathBuf {
    let repo_dir = out_path.join("libafl_symcc_src");
    if !repo_dir.exists() {
        // TODO: use similar approach as for SymQEMU to clone at specific commit
        symcc_libafl::clone_symcc(&repo_dir);
    }

    symcc_libafl::build_symcc(&repo_dir)
}
