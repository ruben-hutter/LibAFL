# SymQEMU Snapshot-Based Symbolic Execution - Proof of Concept

This is a proof-of-concept implementation for state-based symbolic execution with SymQEMU.

## Current Status

### ✅ Implemented
- **SymQemuModule** (`crates/libafl_qemu/src/modules/symqemu.rs`)
  - Module structure for managing symbolic execution
  - FFI binding to `_sym_make_symbolic()`
  - Shared memory initialization for SymCC runtime
  - Integration with LibAFL's EmulatorModule trait

- **SnapshotModule Helper** (`crates/libafl_qemu/src/modules/usermode/snapshot.rs`)
  - Added `is_snapshot_taken()` method

- **Module Exports**
  - SymQemuModule exported for usermode feature

- **Standalone Runner** (this directory)
  - CLI interface for testing
  - Architecture documentation
  - Helper messages for finding addresses

### ⚠️ TODO (for full functionality)
- Hook registration at snapshot address
- Automatic snapshot capture on first hit
- Snapshot restore mechanism
- Buffer marking as symbolic after restore
- QEMU execution loop
- Constraint collection from shared memory
- Constraint parsing and display

## How to Test

### Step 1: Build the Target Binary

```bash
cd ../fuzzer
cargo build
```

This will create `target_main.out` which is the test target.

### Step 2: Run the Proof-of-Concept

```bash
cd ../snapshot_runner
cargo run
```

This will show you help information about required addresses.

### Step 3: Find the Snapshot Address

The snapshot address is where we want to capture the program state - just before the call to `foo()` on line 58 of `harness_main.c`.

```bash
objdump -d ../fuzzer/target_main.out | grep -A 30 '<main>:'
```

Look for the instruction just BEFORE the call to `<foo>`. For example:
```
  4012a5:  call   401196 <foo>
```

The snapshot address would be `0x4012a5` (or whatever appears before the call).

### Step 4: Determine Buffer Address

For now, use a placeholder address like `0x7fffffffe000`. In a full implementation, we would:
- Hook `malloc()` to track where the data buffer is allocated
- Or use symbol resolution to find global buffers
- Or use GDB to find the runtime address

### Step 5: Run with Addresses

```bash
cargo run -- --snapshot-addr 0x4012a5 --buffer-addr 0x7fffffffe000
```

## Expected Output

The tool will display:
- Configuration summary
- Current implementation status
- Architecture diagram
- Next steps for full implementation
- Links to relevant source files

## Architecture

```
┌─────────────────┐
│  Runner (this)  │
└────────┬────────┘
         │
┌────────▼────────┐
│  QemuBuilder    │
│  + modules:     │
│    - Snapshot   │
│    - SymQemu    │
└────────┬────────┘
         │
┌────────▼────────┐
│   QEMU Process  │
│   (usermode)    │
└─────────────────┘
```

## Implementation Plan

### Phase 1: Hook Registration (NEXT)
Register an instruction hook at the snapshot address that:
1. On first hit: Calls `SnapshotModule.snapshot()` to capture state
2. On subsequent hits: Calls `SymQemuModule.mark_buffer_symbolic()`

### Phase 2: Execution Flow
1. Initialize QEMU with modules
2. Write test input to buffer (starting with "QEMU" to trigger foo path)
3. Run until snapshot hook fires
4. Restore snapshot
5. Mark buffer symbolic
6. Resume execution
7. Collect constraints from shared memory

### Phase 3: Constraint Collection
1. Read constraint trace from shared memory
2. Parse SymExpr format
3. Display constraints in human-readable form

### Phase 4: Integration
1. Integrate with concolic fuzzing loop
2. Add Z3 solver for test generation
3. Full end-to-end concolic fuzzing

## Files Modified/Created

### Created:
- `crates/libafl_qemu/src/modules/symqemu.rs`
- `snapshot_runner/` (this directory)
- `snapshot_runner/src/main.rs`
- `snapshot_runner/Cargo.toml`
- `snapshot_runner/README.md` (this file)

### Modified:
- `crates/libafl_qemu/src/modules/mod.rs` - exported SymQemuModule
- `crates/libafl_qemu/src/modules/usermode/snapshot.rs` - added `is_snapshot_taken()`

## Next Steps

1. Study LibAFL hook API in `crates/libafl_qemu/src/emu/hooks.rs`
2. Implement hook registration in SymQemuModule
3. Test snapshot capture and restore
4. Verify symbolic marking works with SymQEMU runtime
5. Implement constraint collection and parsing

## References

- **LibAFL QEMU Documentation**: Understanding the executor and module system
- **SymCC Documentation**: How `_sym_make_symbolic()` works
- **SymQEMU Documentation**: Runtime integration with QEMU
- **Plan Document**: `/home/device-admin/.claude/plans/sassy-jumping-koala.md`
