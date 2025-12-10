#!/usr/bin/env bash
# Cleanup script for fuzzer artifacts

set -e

# Remove crashes directory
if [ -d "crashes" ]; then
    echo "  Removing crashes/"
    rm -rf crashes
fi

# Clean tmp_corpus (including hidden files)
if [ -d "tmp_corpus" ]; then
    echo "  Cleaning tmp_corpus/"
    rm -rf tmp_corpus/*
    rm -rf tmp_corpus/.*
fi

# Remove hidden files from corpus (but keep the directory and regular files)
if [ -d "corpus" ]; then
    echo "  Removing hidden files from corpus/"
    find corpus -name ".*" -type f -delete
fi

