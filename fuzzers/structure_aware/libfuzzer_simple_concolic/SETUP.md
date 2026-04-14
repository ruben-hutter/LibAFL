# Setup notes

This file captures environment setup that does **not** live in the repo — things
a fresh server or workstation needs before `just build-release` will succeed.
The in-repo pieces (`rust-toolchain.toml`, `.cargo/config.toml`) are committed
separately.

## Toolchain

The project runtime's `Cargo.lock` is in format v4, which requires
`cargo >= 1.78`. System-packaged rust (e.g. Debian `rustc` 1.75) is too old and
fails with `lock file version 4 requires -Znext-lockfile-bump`.

Install rustup + a modern stable toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
```

Verify with `cargo --version` (should report at least 1.85).

### Making rustup visible to non-interactive ssh

rustup's installer appends `. "$HOME/.cargo/env"` to `~/.bashrc`, but Debian's
default `~/.bashrc` has an early return for non-interactive shells:

```bash
case $- in
    *i*) ;;
      *) return;;
esac
```

which means `ssh host cargo build` still picks up the system `/usr/bin/cargo`.
Add an explicit `PATH` export **above** that block:

```bash
# ~/.bashrc, near the top (before the non-interactive early return)
export PATH="$HOME/.cargo/bin:$PATH"
```

## LibAFL lint regressions (current feature branch)

Recent stable rustc (>= 1.94) promotes a few new lints to errors inside
`libafl_bolts` / `libafl` on the `feature/simple-concolic-symqemu` branch:

- `function-casts-as-integer` in `libafl_bolts/src/os/unix_signals.rs`
- `unused_variables` / `unused_assignments` in `libafl_bolts/src/llmp.rs`

The repo works around this with `.cargo/config.toml` at this project's root:

```toml
[build]
rustflags = ["--cap-lints=warn"]
```

This caps all lints at warning level so upstream LibAFL code compiles cleanly
without touching its sources. Drop the workaround once the feature branch is
rebased onto a LibAFL `main` that has fixed those lints.

## SymQEMU / SymCC sources

The build automatically clones:

- `ruben-hutter/symqemu` @ `master` — cloned into
  `fuzzer/target/<profile>/build/libfuzzer_simple_concolic-*/out/symqemu` on
  first build, unless `SYMQEMU_DIR` is set.
- `AFLplusplus/symcc` @ pinned commit `1330e29` — cloned into the same
  `out/` directory.

`symqemu_libafl::clone_symqemu` only initializes the `subprojects/symcc-rt`
submodule (via `git submodule update --init --depth 1 subprojects/symcc-rt`),
**not** `--recursive`. The dead QEMU ROM submodules under `roms/*` and
`tests/lcitool/libvirt-ci` in the upstream fork are never touched and do not
block the build.

If you want to reuse an external SymQEMU checkout (faster iteration, easier
debugging), set `SYMQEMU_DIR`, e.g.:

```bash
export SYMQEMU_DIR="$HOME/symqemu"
just build-release
```

## Runtime environment

`qemu-x86_64` loads `libSymCCRtShared.so` (copied into `fuzzer/` by the build
script) which in turn dlopens `libSymRuntime.so` from the runtime's
`target/release`. The fuzzer binary itself also needs to find these libraries
at run time. Set:

```bash
export LD_LIBRARY_PATH="$HOME/LibAFL/fuzzers/structure_aware/libfuzzer_simple_concolic/fuzzer"
```

or source it from `~/.profile` for interactive/login shells. Non-interactive
ssh sessions do not read `~/.profile` — set it explicitly in the command if
running over ssh.

## Known issues on this branch

- Concolic tracing buffer comes back empty (`ConcolicObserver` reports
  `Buffer is EMPTY - runtime wrote NO symbolic data!`) — under investigation
  on this feature branch, unrelated to the build. Possible causes are listed
  in the warning output itself.
