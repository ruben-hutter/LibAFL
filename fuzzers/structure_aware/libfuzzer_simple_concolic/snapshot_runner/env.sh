#!/bin/bash
# Environment for building/running against the hybrid QEMU tree.
# Usage: source ./env.sh
export LIBAFL_QEMU_DIR=/home/device-admin/LibAFL/fuzzers/structure_aware/libfuzzer_simple_concolic/qemu-hybrid
export LLVM_CONFIG_PATH=/usr/lib/llvm-20/bin/llvm-config
export CC=clang
export CXX=clang++
export LD_LIBRARY_PATH=/home/device-admin/LibAFL/fuzzers/structure_aware/libfuzzer_simple_concolic/qemu-hybrid/build:$LD_LIBRARY_PATH
export RUSTFLAGS="--cap-lints=warn"
