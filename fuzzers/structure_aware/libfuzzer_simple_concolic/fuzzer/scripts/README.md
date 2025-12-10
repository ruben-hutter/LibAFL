# Fuzzer Scripts

This directory contains helper scripts for running and managing the fuzzer.

## Scripts

### run_fuzzing.sh
Starts the fuzzer with multiple clients in a tmux session.

**Usage:**
```bash
./scripts/run_fuzzing.sh <num_regular_clients> <num_concolic_clients>
```

**Arguments:**
- `num_regular_clients`: Number of regular fuzzing clients (coverage-guided)
- `num_concolic_clients`: Number of concolic clients (using SymQEMU with rust_backend)

**Example:**
```bash
# 1 regular client + 1 concolic client
./scripts/run_fuzzing.sh 1 1

# 2 regular clients + 1 concolic client  
./scripts/run_fuzzing.sh 2 1
```

**Logs:**
All output is logged to `logs/` directory:
- `logs/broker.log` - Broker output (shows global stats)
- `logs/regular_client_N.log` - Regular fuzzing client logs
- `logs/concolic_client_N.log` - Concolic client logs

**Tmux Session:**
- Session name: `libafl_fuzz`
- Attach: `tmux attach -t libafl_fuzz`
- Kill: `tmux kill-session -t libafl_fuzz`

### clean.sh
Cleans fuzzing artifacts (corpus, crashes, logs, etc).

**Usage:**
```bash
./scripts/clean.sh
```

**Removes:**
- `corpus/` - Fuzzing corpus
- `crashes/` - Crash files
- `logs/` - Log files
- `tmp_corpus/` - Temporary corpus
- `cur_input` - Current input file

## Using with Just

From the project root (`libfuzzer_simple_concolic/`):

```bash
# Run fuzzer (1 regular + 1 concolic)
just run 1 1

# Run fuzzer (2 regular + 1 concolic)
just run 2 1

# Clean artifacts
just clean-artifacts

# Full clean (cargo clean + artifacts)
just clean-all
```
