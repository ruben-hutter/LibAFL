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

### Phase 0 — Secure work (~30 min) [DONE]
### Phase 1 — Make libafl_qemu compile [DONE, d4045474]
### Phase 2 — Hybrid QEMU tree [DONE]
- qemu-hybrid/ = bridge 0bea78a (QEMU 10.0) + symqemu delta vs vanilla 9.1.1
  (3-way applied, conflicts resolved; local git history documents everything).
- Builds via libafl_qemu_build with LIBAFL_QEMU_DIR (see snapshot_runner/env.sh).
- symcc-rt rust backend, _rsym_* intentionally unresolved (resolved by the host
  process at load time). Configure needs: CC=clang CXX=clang++ (meson probes
  clang, emits -Wthread-safety), symcc_rt_backend defaults to rust.

### Phase 3a — SymQemuModule fixes [DONE]
- FFI signature, g2h, no duplicate shmem, per-exec trace finalize (15981ac5).

### Phase 3b — snapshot_runner real smoke test [DONE, 15981ac5]
- PASSED: run-to-entry, snapshot, per-input restore+write+mark-symbolic+run,
  4k+ symbolic expressions per execution, snapshot restore ~17us.
- Key learnings: single runtime instance (host links libSymRuntime.so directly,
  shim must NOT link it); trace length header needs explicit end/begin per
  execution (this was also the root cause of the old empty-trace bug);
  --dynamic-list/-E exports don't survive rust-lld + gc-sections for PIE.

### Phase 3c — Fuzzer integration [IN PROGRESS]
- Replace the spawn-child --use-snapshot configurator with the in-process
  emulator flow (as in snapshot_runner/src/main.rs) inside ConcolicTracingStage.
- Fuzzer needs: libafl_qemu dep (usermode+shared), link SymRuntime +
  SymCCRtShared via build.rs rpaths (copy snapshot_runner/build.rs approach),
  build with snapshot_runner/env.sh environment.

### Phase 4 — End-to-end validation (just run-snapshot)
- Assert non-empty traces, Z3 solutions for foo()'s nested conditions,
  compare exec/speed vs forkserver/separate modes.

### Fallback
If Phase 2 merge fails badly, the committed fork-server mode is a
demonstrable milestone on its own. (No longer needed.)
