# Simple Concolic Fuzzer with SymQEMU and SymCC

This folder contains a simple example of hybrid fuzzing using concolic execution with both SymQEMU (runtime instrumentation) and SymCC (compile-time instrumentation).

It has been tested on Linux only, as SymCC and SymQEMU only work on Linux.

The fuzzer itself is in the `fuzzer` directory and the concolic runtime lives in `runtime`.

## System Dependencies

Before building, ensure you have the following system dependencies installed:
- clang and clang++ (LLVM 11 or later)
- cmake
- meson and ninja (for building SymQEMU)
- pkg-config
- git
- Z3 solver (`libz3-dev` on Debian/Ubuntu)

## Automated Build

The build process is fully automated. Simply run:

```bash
cargo build --release
```

This single command will:
1. Build the LibAFL Rust runtime for concolic execution
2. Clone and build AFL++ SymCC fork with rust_backend
3. Clone and build SymQEMU with rust_backend integration (on first build)
4. Compile three versions of the target harness:
   - `harness.c` - with sanitizer coverage for fuzzing
   - `harness_main.c` - for SymQEMU runtime instrumentation
   - `harness_symcc.c` - with SymCC compile-time instrumentation

On first build, this may take 10-15 minutes as it clones and builds SymQEMU. Subsequent builds are much faster as everything is cached.

### Using a Custom SymQEMU Build

If you already have SymQEMU built elsewhere, you can skip the automatic clone/build by setting the `SYMQEMU_DIR` environment variable:

```bash
SYMQEMU_DIR=/path/to/your/symqemu cargo build --release
```

The build system will automatically:
- Use your existing SymQEMU if already built
- Build it if not already built
- Rebuild it if the Rust runtime was updated
- Verify it's configured with the rust_backend

## Run

The first time you run the binary (`target/release/libfuzzer_stb_image_concolic`), the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel.
