//! This is a 'meta-package' for LibAFL that exposes a consistent URL and commit hash for the
//! [`SymQEMU` fork](https://github.com/ruben-hutter/symqemu) with AFL++ rust_backend support.

/// The URL of the `SymQEMU` fork with AFL++ rust_backend integration.
pub const SYMQEMU_REPO_URL: &str = "https://github.com/ruben-hutter/symqemu.git";
/// The branch of the `SymQEMU` fork to use.
pub const SYMQEMU_REPO_BRANCH: &str = "master";

#[cfg(feature = "clone")]
mod clone {
    use std::{
        io::{stdout, Write},
        path::Path,
        process::Command,
    };

    use which::which;

    use crate::{SYMQEMU_REPO_BRANCH, SYMQEMU_REPO_URL};

    /// Clones the SymQEMU repository with the given URL and branch, and initializes submodules.
    /// Any errors will trigger a panic.
    pub fn clone_symqemu_at_version(path: &Path, url: &str, branch: &str) {
        assert!(
            which("git").is_ok(),
            "ERROR: unable to find git. Git is required to download SymQEMU."
        );

        // Clone the repository
        let mut cmd = Command::new("git");
        cmd.arg("clone")
            .arg("--branch")
            .arg(branch)
            .arg(url)
            .arg(path);
        let output = cmd.output().expect("failed to execute git clone");
        if !output.status.success() {
            eprintln!("failed to clone SymQEMU git repository:");
            let mut stdout = stdout();
            stdout
                .write_all(&output.stderr)
                .expect("failed to write git error message to stdout");
            panic!();
        }

        // Initialize and update submodules (especially symcc-rt)
        let mut cmd = Command::new("git");
        cmd.arg("submodule")
            .arg("update")
            .arg("--init")
            .arg("--recursive")
            .arg("--depth")
            .arg("1")
            .current_dir(path);
        let output = cmd
            .output()
            .expect("failed to execute git submodule update");
        if !output.status.success() {
            eprintln!("failed to initialize SymQEMU submodules:");
            let mut stdout = stdout();
            stdout
                .write_all(&output.stderr)
                .expect("failed to write git error message to stdout");
            panic!();
        }

        println!("Successfully cloned SymQEMU with submodules");
    }

    /// Checks out the repository into the given directory.
    /// Any errors will trigger a panic.
    pub fn clone_symqemu(path: &Path) {
        clone_symqemu_at_version(path, SYMQEMU_REPO_URL, SYMQEMU_REPO_BRANCH);
    }
}

#[cfg(feature = "clone")]
pub use clone::clone_symqemu;

#[cfg(feature = "build")]
mod build {
    #![allow(clippy::module_name_repetitions)]

    use std::{
        io::{stdout, Write},
        path::{Path, PathBuf},
        process::Command,
    };

    /// Builds `SymQEMU` at the given directory using meson and ninja.
    /// Configures it with `-Dsymcc_rt_backend=rust` to use the LibAFL rust_backend.
    /// Returns the build artifact directory.
    #[must_use]
    pub fn build_symqemu(path: &Path) -> PathBuf {
        let build_dir = path.join("build");

        // Run meson setup if build directory doesn't exist
        if !build_dir.exists() {
            println!("Running meson setup for SymQEMU...");
            let output = Command::new("meson")
                .arg("setup")
                .arg(&build_dir)
                .arg("-Dsymcc_rt_backend=rust")
                .current_dir(path)
                .output()
                .expect("failed to execute meson setup");

            if !output.status.success() {
                eprintln!("meson setup failed:");
                let mut stdout = stdout();
                stdout
                    .write_all(&output.stderr)
                    .expect("failed to write meson error message to stdout");
                panic!();
            }
        } else {
            // Configure with rust backend if already set up
            println!("Configuring SymQEMU with rust_backend...");
            let output = Command::new("meson")
                .arg("configure")
                .arg(&build_dir)
                .arg("-Dsymcc_rt_backend=rust")
                .current_dir(path)
                .output()
                .expect("failed to execute meson configure");

            if !output.status.success() {
                eprintln!("meson configure failed:");
                let mut stdout = stdout();
                stdout
                    .write_all(&output.stderr)
                    .expect("failed to write meson error message to stdout");
                panic!();
            }
        }

        // Build with ninja
        println!("Building SymQEMU with ninja...");
        let output = Command::new("ninja")
            .arg("-C")
            .arg(&build_dir)
            .current_dir(path)
            .output()
            .expect("failed to execute ninja");

        if !output.status.success() {
            eprintln!("ninja build failed:");
            let mut stdout = stdout();
            stdout
                .write_all(&output.stderr)
                .expect("failed to write ninja error message to stdout");
            panic!();
        }

        println!("SymQEMU built successfully at {:?}", build_dir);
        build_dir
    }
}

#[cfg(feature = "build")]
pub use build::build_symqemu;
