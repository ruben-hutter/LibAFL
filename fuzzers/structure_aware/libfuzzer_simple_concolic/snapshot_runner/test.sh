#!/bin/bash

# Quick test script for the snapshot runner proof-of-concept

set -e

echo "========================================"
echo "Testing SymQEMU Snapshot Runner PoC"
echo "========================================"
echo

# Step 1: Build the target if needed
echo "[1/3] Checking if target binary exists..."
if [ ! -f "../fuzzer/target_main.out" ]; then
    echo "      Target not found. Building..."
    cd ../fuzzer
    cargo build
    cd ../snapshot_runner
else
    echo "      ✓ Target binary found"
fi

echo

# Step 2: Build the runner
echo "[2/3] Building snapshot runner..."
cargo build
echo "      ✓ Runner built"

echo

# Step 3: Run the PoC
echo "[3/3] Running proof-of-concept..."
echo

cargo run

echo
echo "========================================"
echo "Test complete!"
echo "========================================"
echo
echo "Next steps:"
echo "  1. Find the snapshot address using objdump"
echo "  2. Run with addresses to see full PoC output"
echo
echo "See README.md for detailed instructions"
