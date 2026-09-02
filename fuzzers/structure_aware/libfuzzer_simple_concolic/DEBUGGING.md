# Debugging the restored-execution constraint loss — RESOLVED

**Status: FIXED** (see commits `91670909` and `e29b3739`). Kept for the
postmortem.

## Follow-up fix: in-process crash handling (`e29b3739`)

After the PC fix, Z3 quickly solved the full constraint chain and the
native harness hit the intended NULL deref during mutation evaluation -
and the process died with 'QEMU internal SIGSEGV' (exit 1). Root cause:
QEMU's signal_init (at lazy emulator boot) overwrites the fuzzer's
SIGSEGV handler; the bridge's die_with_signal re-raises the signal
expecting the fuzzer's handler to catch it, but re-raising into our own
handler recursed. Fix: signal_init saves pre-existing host actions for
fatal signals; die_with_signal restores them before re-raising. Plus
set_target_crash_handling(ReturnToHarness) so guest crashes return as
QemuExitReason::Crash instead of taking the signal path at all.

Result: the fuzzer finds the crash (objectives stored, crash input =
the exact Z3 solution) and keeps fuzzing.

## Root cause

`SnapshotModule::reset` (libafl_qemu usermode snapshot) restores guest RAM
pages, mappings and mprotect states — but **NOT the CPU registers, including
the PC**. This is by design: the intended libafl_qemu usage has the *guest*
re-enter the entry function itself (guest-side fuzzing loop via the
`start_fuzzing` backdoor), and the other established pattern
(`fuzzers/binary_only/fuzzbench_qemu`) explicitly writes `Rip/Rsp/Rdi/Rsi`
before every `qemu.run()` — for exactly this reason.

The snapshot executor assumed `reset()` rewinds the PC. It doesn't. After the
first iteration stopped at the (still armed) return-address breakpoint, every
following `qemu.run()` resumed AT that breakpoint and returned immediately —
**zero guest instructions executed**. The concolic trace then contained only
the marking's InputByte expressions (which are produced host-side, outside
the guest), no path constraints, so Z3 starved.

## The overlooked evidence

The per-iteration timings had the answer all along: iteration 0 took
~600µs-1.4ms (full harness execution under TCG), iterations 1+ took ~17-220µs
(zero instructions — immediate breakpoint hit). The 'fast snapshot restore'
was actually 'no execution at all'.

This also explains why every earlier mitigation failed: neither `tb_flush`,
nor zeroing `env_exprs`/shadow pages, nor any translation-side change could
matter — nothing ever re-executed.

## Fix

Capture `Rip/Rsp/Rdi/Rsi` at the entry breakpoint during init; rewrite them
explicitly after every `SnapshotModule::reset` (fuzzbench_qemu pattern).
The per-iteration `libafl_flush_jit()` is dropped (translated blocks carry
no persistent symbolic state; the env_exprs region and shadow pages are
zeroed via `_libafl_sym_reset_state` before re-marking, which keeps
expression ids consistent with the per-trace writer rewind).

## Verification

- smoke test (`snapshot_runner`): every iteration yields a full constraint
  trace, path-dependent (`{InputByte 16, Integer 20, PathConstraint 5,
  other 35}` for foo-paths, `{InputByte 16, Integer 8, PathConstraint 2,
  other 15}` for bar-paths).
- fuzzer (`just run-snapshot`): steady-state histograms show PathConstraint
  on every trace; Z3 generates 1-5 mutations per iteration; corpus grows;
  edges climb (50% -> 61% in the verification run).
