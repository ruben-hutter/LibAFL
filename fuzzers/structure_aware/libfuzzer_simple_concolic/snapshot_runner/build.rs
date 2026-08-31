fn main() {
    let runtime_dir = std::path::Path::new("..")
        .join("runtime")
        .join("target")
        .join("release")
        .canonicalize()
        .expect("runtime not built yet: cargo build --release in ../runtime");
    let shim_dir = std::path::Path::new("..")
        .join("qemu-hybrid")
        .join("build")
        .join("subprojects")
        .join("symcc-rt")
        .canonicalize()
        .expect("hybrid QEMU not built yet");
    let qemu_dir = std::path::Path::new("..")
        .join("qemu-hybrid")
        .join("build")
        .canonicalize()
        .expect("hybrid QEMU not built yet");

    println!("cargo:rustc-link-search=native={}", runtime_dir.display());
    println!("cargo:rustc-link-lib=dylib=SymRuntime");
    // The SymCC C++ shim: provides the _sym_* functions used by SymQemuModule.
    println!("cargo:rustc-link-search=native={}", shim_dir.display());
    println!("cargo:rustc-link-lib=dylib=SymCCRtShared");

    // Bake absolute rpaths so the binary runs without LD_LIBRARY_PATH.
    for dir in [&runtime_dir, &shim_dir, &qemu_dir] {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
    }
    println!("cargo:rerun-if-changed=../runtime/src/lib.rs");
}
