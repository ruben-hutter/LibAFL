# Debugging the restored-execution constraint loss (OPEN)

Status as of the last session. Repro: `cd snapshot_runner && source env.sh &&
cargo run` (3 iterations, no LLMP needed). Also reproducible in the fuzzer
(`just run-snapshot`): all iterations after the first produce
`{"InputByte": N}`-only traces (check the histogram line the ConcolicObserver
prints), so Z3 gets no constraints and generates 0 mutations.

## Symptom

- Iteration 0 (first execution after guest boot): full trace
  `{InputByte: 16, Integer: 20, PathConstraint: 5, other: 35}` -> Z3 works.
- Every execution after a `SnapshotModule::restore`:
  `{InputByte: N}` only. The guest's byte loads of the input buffer are
  treated as CONCRETE - `_sym_read_memory` is never consulted for the buffer
  address (verified: buffer-range-instrumented `RuntimeCommon.cpp
  readMemory` fires exactly once, on iteration 0, never again).

## Ruled out

1. Trace id rewind (begin/end): not the cause - traces decode fully.
2. `CallStackCoverage` filter: removed entirely (separate fix).
3. Stale shim: `just run 0 1` re-copies the old standalone
   `fuzzer/libSymCCRtShared.so`; run-snapshot now deletes it (justfile).
   Ensure the loaded shim is `qemu-hybrid/build/subprojects/symcc-rt/...`
   (check /proc/<client>/maps).
4. `tb_flush` (libafl_flush_jit) + zeroing `env_exprs` region + zeroing
   shadow pages (`_libafl_sym_reset_state`): none restore symbolic loads.
5. The restore experiment (SMOKE_NO_RESTORE=1): with NO restore, iterations
   re-hit the pending ret_addr breakpoint and execute ZERO guest
   instructions (InputBytes come from marking only) - that is a SEPARATE
   smoke-test artifact, not the fuzzer bug. In the fuzzer, the restore DOES
   rewind PC to the entry and the guest does execute foo (ret breakpoint
   fires) - yet loads are still concrete.

## Leading hypothesis

`SnapshotModule::reset` (libafl_qemu usermode snapshot restore) restores
CPUArchState + guest RAM but leaves the process in a state where
`sym_load_guest_*` helpers are absent from the re-executed TBs. Evidence:
- translation-side counter (`sym_ldst_i64_translated` in tcg-op-ldst.c)
  stops growing after boot; iterations never re-translate through the
  symbolic path;
- yet the ret_addr breakpoint fires, so foo's body does execute.

Next steps to try (in order):
1. Dump the executed TB for foo's body on iteration >= 1:
   `SNAPSHOT_TRACE_TCG=1` + grep the dump for the foo PC range
   (0x555555557196..0x555555557412) and check whether
   `call sym_load_guest_i64` appears.
2. Compare with the iteration-0 TB (same dump, before the first restore).
3. If the retranslated TB lacks `sym_load_guest_*`, diff the translation
   context: check `cflags` (CF_NO_GOTO_TB etc.), `tb_flush` behavior of
   `libafl_flush_jit`, and whether `cpu->tcg_cflags` changed after restore
   (SnapshotModule / libafl bridge save-restore in libafl_user.c).
4. Alternative: skip SnapshotModule entirely - snapshot CPU+RAM manually
   via the bridge (`libafl_save_autosave`/restore or own memcpy of
   guest RAM regions + CPU regs) and see whether symbolic loads survive;
   that isolates whether the breakage is in the snapshot mechanics or in
   the restore of CPU state fields that carry symbolic metadata.
