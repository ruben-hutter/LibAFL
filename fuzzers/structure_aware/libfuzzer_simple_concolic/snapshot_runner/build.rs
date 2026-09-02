fn main() {
    // Link the SymCC C++ shim (provides _libafl_sym_reset_state and the
    // _sym_* runtime) plus the LibAFL rust runtime it forwards to, with
    // absolute rpaths so the snapshot runner works without LD_LIBRARY_PATH.
    let base = std::path::Path::new("..").canonicalize().unwrap();
    let shim_dir = base
        .join("qemu-hybrid")
        .join("build")
        .join("subprojects")
        .join("symcc-rt");
    let qemu_dir = base.join("qemu-hybrid").join("build");
    let runtime_dir = base.join("runtime").join("target").join("release");

    println!("cargo:rustc-link-search=native={}", shim_dir.display());
    println!("cargo:rustc-link-lib=dylib=SymCCRtShared");
    println!("cargo:rustc-link-search=native={}", runtime_dir.display());
    println!("cargo:rustc-link-lib=dylib=SymRuntime");
    for dir in [&shim_dir, &qemu_dir, &runtime_dir] {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
    }
}
