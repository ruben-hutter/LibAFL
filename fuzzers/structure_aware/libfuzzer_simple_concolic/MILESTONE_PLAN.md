# Milestone Plan: Snapshot-Based Concolic Execution over SymQEMU (Route A)

Status: approved 2026-08-31. Branch: `feature/simple-concolic-symqemu`.

## Goal

Concolic fuzzing over SymQEMU using snapshot-based execution: run the target
normally until the entry point (e.g. `LLVMFuzzerTestOneInput`), snapshot the full
CPU/memory state there, then per input: restore -> write input into the guest
buffer -> mark it symbolic -> resume under SymQEMU's symbolic TCG instrumentation
-> collect the concolic trace from shmem -> solve with Z3
(`SimpleConcolicMutationalStage`) -> feed solutions back to the fuzzer.

Chosen route: **A (libafl_qemu)** — build `libafl_qemu` against a hybrid QEMU
tree that contains BOTH the LibAFL bridge AND SymQEMU's symbolic
instrumentation, then drive `ConcolicSnapshotModule` from an in-process
executor.

## Current state (2026-08-31 audit)

- Fuzzer skeleton with 4 concolic modes (`fuzzer/src/main.rs`):
  `separate`/`symcc`/`forkserver`/`snapshot`. Pipeline
  `ConcolicTracingStage` -> `SimpleConcolicMutationalStage` wired.
- Rust concolic runtime (`runtime/src/lib.rs` -> `libSymRuntime.so`): works,
  linked into SymQEMU via `symqemu_libafl` + CMake patch.
- `ConcolicSnapshotModule` (`crates/libafl_qemu/src/modules/usermode/concolic_snapshot.rs`)
  implements the milestone design but has never been compiled or driven.
- `--use-snapshot` fuzzer mode is a placeholder: it sets
  `SYMCC_ENABLE_SNAPSHOT`/`SYMCC_SNAPSHOT_TARGET_FUNCTION` env vars that
  SymQEMU does not implement. Snapshot mode today == separate mode.

### Known gaps / bugs

1. `crates/libafl_qemu/src/modules/mod.rs` never declares `pub mod symqemu;`
   -> `SymQemuModule` not exported -> `concolic_snapshot.rs` cannot compile.
2. Nothing drives `ConcolicSnapshotModule`; `snapshot_runner` is a print-only stub.
3. Architecture gap: `libafl_qemu` builds `qemu-libafl-bridge` @ `0bea78a`
   (QEMU 10.0.0, no symbolic TCG) while SymQEMU is QEMU 9.1.1 (no bridge).
4. `SymQemuModule` bugs:
   - `_sym_make_symbolic` FFI signature wrong (3rd arg is `input_offset: usize`,
     not a label `*const c_char`) — see `runtime/src/lib.rs:546`.
   - passes a guest address where a host pointer is required (needs
     `qemu.g2h()`, `crates/libafl_qemu/src/qemu/usermode.rs:206`).
   - `first_exec` creates a second shmem and overwrites the fuzzer's
     `SHARED_MEMORY_MESSAGES` env var.
5. Empty-trace bug (SETUP.md known issues) only mitigated by the parser fix in
   `crates/libafl/src/observers/concolic/serialization_format.rs` (uncommitted).

### Key facts (de-risking)

- SymQEMU patch vs vanilla v9.1.1: 139 files / ~4.2k insertions, 84 of which
  are tests. Core changes: `accel/tcg/*`, `include/tcg/*`, `tcg/tcg-op*.c`,
  `target/*/tcg/*`, `subprojects/symcc-rt`. Base point: merge commit
  `3f5a25d3dc` ("Merge tag 'v9.1.1'") — second parent is vanilla v9.1.1.
- `libafl_qemu_build` honors env overrides `LIBAFL_QEMU_DIR`,
  `LIBAFL_QEMU_GIT_URL`, `LIBAFL_QEMU_GIT_REV`
  (`crates/libafl_qemu/libafl_qemu_build/src/build.rs:282`). Caution: a
  `QEMU_REVISION` file mismatch triggers `remove_dir_all` on the tree.
- All other APIs used by `ConcolicSnapshotModule` exist (`binary_path`,
  `load_addr`, `instruction_function`, `use_manual_reset`, `EasyElf`).

## Phases

### Phase 0 — Secure work (~30 min) [DONE see git log]
- `.gitignore` for `snapshot_runner/target/`, stray artifacts
  (`fuzzer/dummy_arg`, root `package-lock.json`).
- Commit WIP (snapshot-mode plumbing + parser robustness fix) and untracked
  sources (`fuzzer/harness_snapshot.c`, `snapshot_runner/` sources,
  `MILESTONE_PLAN.md`).
- Push branch (was: 1 unpushed commit + dirty tree).

### Phase 1 — Make libafl_qemu compile (~1-2 h)
- Add `pub mod symqemu;` + re-export `SymQemuModule` in
  `crates/libafl_qemu/src/modules/mod.rs`.
- `cargo check -p libafl_qemu --features usermode`; fix fallout.

### Phase 2 — Hybrid QEMU tree (1-2 days; MAIN RISK)
1. Rescue existing bridge clone out of `snapshot_runner/target/` (wiped by
   cargo clean) into `qemu-hybrid/` at the fuzzer dir root.
2. Generate symqemu patch: `git diff 3f5a25d3dc^2 HEAD` from a full symqemu
   clone, excluding tests where convenient; include `subprojects/symcc-rt`
   submodule + rust_backend CMake patch.
3. Apply onto bridge tree; resolve conflicts (expected in `tcg/tcg-op*.c`,
   `accel/tcg/tcg-runtime.c`, `include/tcg/tcg-op.h`).
4. Configure bridge-style shared-lib build (`libqemu-x86_64.so`) with
   SymQEMU's symbolic backend linked; validate with symqemu's
   `tests/unit/check-sym-runtime.c`.
5. Point builds at the hybrid via `LIBAFL_QEMU_DIR` (manage `QEMU_REVISION`).

### Phase 3 — Executor integration (~0.5-1 day)
- Fix `SymQemuModule` (FFI signature, `g2h()`, drop duplicate shmem init).
- Replace spawn-child snapshot configurator with an in-process `Emulator`
  executor using `ConcolicSnapshotModule` inside the existing
  `ConcolicTracingStage`; `SYMCC_INPUT_FILE` must NOT be set in this mode.
- Turn `snapshot_runner` into a real smoke test of the module.

### Phase 4 — End-to-end validation (~0.5 day)
- `just run-snapshot` on `harness_snapshot.c` (nested conditions are concolic
  bait): assert non-empty trace, Z3 solutions found, solutions reach
  `foo()`'s return-1 path.
- Compare exec/speed vs `forkserver` and `separate`; chase empty-trace root
  cause if it persists.

### Fallback
If Phase 2 merge fails badly, the committed fork-server mode is a
demonstrable milestone on its own.
