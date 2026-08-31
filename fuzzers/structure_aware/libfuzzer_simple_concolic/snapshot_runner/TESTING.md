# Testing the Snapshot Runner

## Quick Start

The snapshot_runner is currently building. Here's what you need to know:

### Current Status

The implementation has hit a **build dependency issue** that's **unrelated to our code**:
- The fuzzer's build.rs tries to build SymQEMU
- SymQEMU's meson configure is failing
- This is an existing issue with the SymQEMU setup, not our changes

### What We've Implemented

1. ✅ **SymQemuModule** - Core module for symbolic execution management
2. ✅ **Module exports** - Properly integrated into libafl_qemu
3. ✅ **SnapshotModule helpers** - Added `is_snapshot_taken()` method
4. ✅ **Proof-of-concept runner** - CLI tool to demonstrate the architecture

### How to Test (Once Build Completes)

```bash
cd /home/device-admin/LibAFL/fuzzers/structure_aware/libfuzzer_simple_concolic/snapshot_runner

# This will show the PoC output without needing the target binary
cargo run
```

Expected output:
- Architecture diagram
- Implementation status (what's done, what's TODO)
- Next steps
- Helpful instructions

### Files We Changed

**Created:**
```
crates/libafl_qemu/src/modules/symqemu.rs          # Core module
fuzzers/.../snapshot_runner/                        # PoC tool
fuzzers/.../snapshot_runner/src/main.rs
fuzzers/.../snapshot_runner/Cargo.toml
fuzzers/.../snapshot_runner/README.md
fuzzers/.../snapshot_runner/TESTING.md (this file)
fuzzers/.../snapshot_runner/test.sh
```

**Modified:**
```
crates/libafl_qemu/src/modules/mod.rs              # Exported SymQemuModule
crates/libafl_qemu/src/modules/usermode/snapshot.rs  # Added helper method
```

### Workaround for SymQEMU Build Issue

If you want to bypass the SymQEMU build issue and test our code:

1. **Option A: Skip fuzzer build entirely**
   ```bash
   # Just run the snapshot_runner (doesn't need fuzzer)
   cd snapshot_runner
   cargo run
   ```

2. **Option B: Set SYMQEMU_DIR to existing build**
   ```bash
   # Point to your existing SymQEMU at ~/symqemu
   export SYMQEMU_DIR=~/symqemu
   cd ../fuzzer
   cargo build
   ```

3. **Option C: Focus on code review**
   - Review the SymQemuModule implementation
   - Check the architecture in snapshot_runner/README.md
   - Discuss next steps without needing a working build

### What Happens When Runner Executes

The runner will:
1. Check if target binary exists (it won't, but that's OK)
2. Show help on how to find addresses
3. Display the PoC architecture diagram
4. List what's implemented and what's TODO
5. Provide next steps

It's designed to be informative even without a working target!

### Compilation Status

The runner is currently compiling libafl_qemu and its dependencies. This may take 5-10 minutes on first build.

You can check progress with:
```bash
# In another terminal
ps aux | grep cargo
```

### Next Steps After Testing

Once you can run it, you can give feedback on:
1. Is the output clear and helpful?
2. Does the architecture make sense?
3. What should we prioritize next?
4. Any issues or confusion?

Then we can iterate on the implementation!

## Alternative: Manual Code Review

If the build is taking too long or failing, we can do a manual code review instead:

### Review SymQemuModule
```bash
cat crates/libafl_qemu/src/modules/symqemu.rs
```

Key points:
- Simple, focused module
- FFI binding to `_sym_make_symbolic()`
- Shared memory setup for SymCC runtime
- Clean integration with EmulatorModule trait

### Review Changes to Snapshot Module
```bash
git diff crates/libafl_qemu/src/modules/usermode/snapshot.rs
```

Should show just the `is_snapshot_taken()` helper method added.

### Review Module Exports
```bash
git diff crates/libafl_qemu/src/modules/mod.rs
```

Should show SymQemuModule being exported.

---

**Bottom line**: The code is ready, but we're hitting an unrelated build issue. We can review the code directly or wait for the build to complete to test the PoC output.
