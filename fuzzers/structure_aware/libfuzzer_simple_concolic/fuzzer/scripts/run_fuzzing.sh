#!/usr/bin/env bash

# Script to run LibAFL fuzzing with multiple clients in a dedicated tmux session
# Broker gets its own window, clients are split 4 per window
# Usage: ./run_fuzzing.sh [num_regular_clients] [num_concolic_clients]

set -e

# Default values
NUM_REGULAR=${1:-2}      # Default: 2 regular fuzzing clients
NUM_CONCOLIC=${2:-1}     # Default: 1 concolic client
CONCOLIC_MODE=${3:-forkserver}  # Concolic mode: forkserver, separate, symcc

# Build mode (can be set via FUZZER_MODE env var, defaults to release)
BUILD_MODE=${FUZZER_MODE:-release}
SESSION_NAME="libafl_fuzz"
FUZZER_BIN="./target/${BUILD_MODE}/libfuzzer_simple_concolic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Starting LibAFL Fuzzing Setup ===${NC}"
echo -e "${BLUE}Build mode: ${BUILD_MODE}${NC}"
echo -e "${BLUE}Regular clients: ${NUM_REGULAR}${NC}"
echo -e "${BLUE}Concolic clients: ${NUM_CONCOLIC} (mode: ${CONCOLIC_MODE})${NC}"
echo ""

# Build (no usermode feature needed for fork-server mode)
# SKIP_BUILD=1 to use the already-built binary (e.g. the qemu-snapshot
# feature build done by `just run-snapshot`; a plain rebuild here would
# overwrite it with a non-feature binary).
if [ -z "$SKIP_BUILD" ]; then
echo -e "${YELLOW}Building fuzzer in ${BUILD_MODE} mode...${NC}"
if [ "$BUILD_MODE" = "release" ]; then
    cargo build --release
else
    cargo build
fi
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
fi

# Get current working directory
WORK_DIR=$(pwd)

# Clean up any existing session
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    echo -e "${YELLOW}Killing existing session '$SESSION_NAME'...${NC}"
    tmux kill-session -t "$SESSION_NAME"
    sleep 1
fi

# Create new tmux session
echo -e "${GREEN}Creating tmux session '$SESSION_NAME'...${NC}"
tmux new-session -d -s "$SESSION_NAME" -n "broker"

# Start broker in first window with logging
echo -e "${YELLOW}Starting broker...${NC}"
tmux send-keys -t "$SESSION_NAME:broker" "cd $WORK_DIR && $FUZZER_BIN" C-m

# Wait a bit for broker to start
sleep 2

# Function to create a pane and run fuzzer
# Args: window_name, pane_index, command
create_pane() {
    local window=$1
    local pane_idx=$2
    local cmd=$3

    if [ $pane_idx -eq 0 ]; then
        tmux send-keys -t "$SESSION_NAME:${window}.0" "cd $WORK_DIR && $cmd" C-m
    else
        if [ $pane_idx -eq 1 ]; then
            tmux split-window -h -t "$SESSION_NAME:$window"
            tmux send-keys -t "$SESSION_NAME:$window" "cd $WORK_DIR && $cmd" C-m
        elif [ $pane_idx -eq 2 ]; then
            tmux select-pane -t "$SESSION_NAME:${window}.0"
            tmux split-window -v -t "$SESSION_NAME:${window}.0"
            tmux send-keys -t "$SESSION_NAME:$window" "cd $WORK_DIR && $cmd" C-m
        else
            tmux select-pane -t "$SESSION_NAME:${window}.1"
            tmux split-window -v -t "$SESSION_NAME:${window}.1"
            tmux send-keys -t "$SESSION_NAME:$window" "cd $WORK_DIR && $cmd" C-m
        fi
    fi
}

# Start regular fuzzing clients
if [ $NUM_REGULAR -gt 0 ]; then
    echo -e "${YELLOW}Creating regular clients...${NC}"

    num_windows=$(( ($NUM_REGULAR + 3) / 4 ))  # Ceiling division

    for win in $(seq 1 $num_windows); do
        window_name="regular_${win}"
        tmux new-window -t "$SESSION_NAME" -n "$window_name"

        start_idx=$(( ($win - 1) * 4 + 1 ))
        end_idx=$(( $win * 4 ))
        if [ $end_idx -gt $NUM_REGULAR ]; then
            end_idx=$NUM_REGULAR
        fi

        pane_idx=0
        for i in $(seq $start_idx $end_idx); do
            echo -e "${BLUE}  Starting regular client #$i (window $win, pane $pane_idx)${NC}"
            create_pane "$window_name" $pane_idx "$FUZZER_BIN"
            pane_idx=$((pane_idx + 1))
            sleep 2
        done

        tmux select-layout -t "$SESSION_NAME:$window_name" tiled
    done
fi

# Determine concolic command based on mode
case "$CONCOLIC_MODE" in
    forkserver)
        CONCOLIC_CMD="$FUZZER_BIN --concolic --use-forkserver"
        ;;
    snapshot)
        CONCOLIC_CMD="$FUZZER_BIN --concolic --use-snapshot"
        ;;
    separate)
        CONCOLIC_CMD="$FUZZER_BIN --concolic"
        ;;
    symcc)
        CONCOLIC_CMD="$FUZZER_BIN --concolic --use-symcc"
        ;;
    *)
        echo -e "${RED}Unknown concolic mode: ${CONCOLIC_MODE}${NC}"
        echo "Valid modes: forkserver, snapshot, separate, symcc"
        exit 1
        ;;
esac

# Start concolic clients
if [ $NUM_CONCOLIC -gt 0 ]; then
    echo -e "${YELLOW}Creating concolic clients (${CONCOLIC_MODE} mode)...${NC}"

    num_windows=$(( ($NUM_CONCOLIC + 3) / 4 ))  # Ceiling division

    for win in $(seq 1 $num_windows); do
        window_name="concolic_${win}"
        tmux new-window -t "$SESSION_NAME" -n "$window_name"

        start_idx=$(( ($win - 1) * 4 + 1 ))
        end_idx=$(( $win * 4 ))
        if [ $end_idx -gt $NUM_CONCOLIC ]; then
            end_idx=$NUM_CONCOLIC
        fi

        pane_idx=0
        for i in $(seq $start_idx $end_idx); do
            echo -e "${BLUE}  Starting concolic client #$i (${CONCOLIC_MODE}, window $win, pane $pane_idx)${NC}"
            create_pane "$window_name" $pane_idx "$CONCOLIC_CMD"
            pane_idx=$((pane_idx + 1))
            sleep 2
        done

        tmux select-layout -t "$SESSION_NAME:$window_name" tiled
    done
fi

echo ""
echo -e "${GREEN}=== Fuzzing setup complete! ===${NC}"
echo -e "${BLUE}Session: $SESSION_NAME${NC}"
echo ""
echo "Just recipes (justfile one level up, run them from there):"
if command -v just >/dev/null 2>&1 && [ -f "$WORK_DIR/../justfile" ]; then
    just --justfile "$WORK_DIR/../justfile" --list
else
    echo -e "  ${YELLOW}(just or justfile not found)${NC}"
fi
echo ""
echo "tmux commands:"
echo -e "  ${YELLOW}tmux attach -t $SESSION_NAME${NC}       - Attach to session"
echo -e "  ${YELLOW}tmux kill-session -t $SESSION_NAME${NC} - Kill entire session (clean restart)"
echo -e "  ${YELLOW}Ctrl+B then D${NC}                      - Detach from session"
echo -e "  ${YELLOW}Ctrl+B then W${NC}                      - List all windows"
echo -e "  ${YELLOW}Ctrl+B then N/P${NC}                    - Next/Previous window"
echo -e "  ${YELLOW}Ctrl+B then Arrow${NC}                  - Navigate between panes"
echo -e "  ${YELLOW}Ctrl+B then Z${NC}                      - Zoom current pane (toggle)"
echo ""
echo "Layout: Broker in separate window, 4 clients per window in tiled layout"
echo ""
