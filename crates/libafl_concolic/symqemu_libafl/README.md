# symqemu_libafl

A meta-package for LibAFL that provides helper functions to automatically clone and build SymQEMU with AFL++ rust_backend support.

## Purpose

This crate exposes a consistent repository URL and branch for the SymQEMU fork that includes AFL++ rust_backend integration. It provides helper functions to automate the process of:
- Cloning the SymQEMU repository with submodules
- Building SymQEMU with meson/ninja configured for rust_backend

## Usage

Add this to your `Cargo.toml` as a build dependency:

```toml
[build-dependencies]
symqemu_libafl = { path = "path/to/symqemu_libafl" }
```

In your `build.rs`:

```rust
use std::path::Path;
use symqemu_libafl::{clone_symqemu, build_symqemu};

fn main() {
    let symqemu_dir = Path::new("path/to/symqemu");

    // Clone SymQEMU if it doesn't exist
    if !symqemu_dir.exists() {
        clone_symqemu(&symqemu_dir);
    }

    // Build SymQEMU with rust_backend
    let build_dir = build_symqemu(&symqemu_dir);

    // build_dir now points to the build artifacts
    println!("SymQEMU built at: {:?}", build_dir);
}
```

## Features

- `clone` (default): Enables the `clone_symqemu()` function
- `build` (default): Enables the `build_symqemu()` function

## Repository

The SymQEMU fork used by this crate is maintained at:
- URL: https://github.com/ruben-hutter/symqemu
- Branch: master

This fork includes:
- Integration with AFL++ SymCC runtime
- Support for the LibAFL rust_backend
- The symcc-rt submodule with Rust backend support
