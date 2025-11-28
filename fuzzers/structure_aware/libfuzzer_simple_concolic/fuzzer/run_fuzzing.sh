#!/usr/bin/env bash

# Script to run LibAFL fuzzing with multiple clients in a dedicated tmux session
# Broker gets its own window, clients are split 4 per window
# Usage: ./run_fuzzing.sh [num_regular_clients] [num_concolic_clients]

set -e

# Default values
NUM_REGULAR=${1:-2}      # Default: 2 regular fuzzing clients
NUM_CONCOLIC=${2:-1}     # Default: 1 concolic client (with SymCC)

SESSION_NAME="libafl_fuzz"
FUZZER_BIN="./target/release/libfuzzer_simple_concolic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Starting LibAFL Fuzzing Setup ===${NC}"
echo -e "${BLUE}Regular clients: ${NUM_REGULAR}${NC}"
echo -e "${BLUE}Concolic clients: ${NUM_CONCOLIC} (using SymCC)${NC}"
echo ""

# Check if binary exists
if [ ! -f "$FUZZER_BIN" ]; then
    echo -e "${RED}Error: Fuzzer binary not found at $FUZZER_BIN${NC}"
    echo -e "${YELLOW}Building fuzzer...${NC}"
    cargo build --release
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

# Start broker in first window
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
        # First pane already exists, just run command
        tmux send-keys -t "$SESSION_NAME:${window}.0" "cd $WORK_DIR && $cmd" C-m
    else
        # Split the window and run command in the newly created pane
        if [ $pane_idx -eq 1 ]; then
            # First split: vertical (left/right)
            tmux split-window -h -t "$SESSION_NAME:$window"
            tmux send-keys -t "$SESSION_NAME:$window" "cd $WORK_DIR && $cmd" C-m
        elif [ $pane_idx -eq 2 ]; then
            # Second split: split left pane horizontally (top/bottom)
            tmux select-pane -t "$SESSION_NAME:${window}.0"
            tmux split-window -v -t "$SESSION_NAME:${window}.0"
            tmux send-keys -t "$SESSION_NAME:$window" "cd $WORK_DIR && $cmd" C-m
        else
            # Third split: split right pane horizontally (top/bottom)
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

        # Calculate how many clients in this window
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

        # Balance the panes for even layout
        tmux select-layout -t "$SESSION_NAME:$window_name" tiled
    done
fi

# Start concolic clients (using SymCC)
if [ $NUM_CONCOLIC -gt 0 ]; then
    echo -e "${YELLOW}Creating concolic clients (SymCC)...${NC}"

    num_windows=$(( ($NUM_CONCOLIC + 3) / 4 ))  # Ceiling division

    for win in $(seq 1 $num_windows); do
        window_name="concolic_${win}"
        tmux new-window -t "$SESSION_NAME" -n "$window_name"

        # Calculate how many clients in this window
        start_idx=$(( ($win - 1) * 4 + 1 ))
        end_idx=$(( $win * 4 ))
        if [ $end_idx -gt $NUM_CONCOLIC ]; then
            end_idx=$NUM_CONCOLIC
        fi

        pane_idx=0
        for i in $(seq $start_idx $end_idx); do
            echo -e "${BLUE}  Starting concolic client #$i (window $win, pane $pane_idx)${NC}"
            create_pane "$window_name" $pane_idx "$FUZZER_BIN --concolic --use-symcc"
            pane_idx=$((pane_idx + 1))
            sleep 2
        done

        # Balance the panes for even layout
        tmux select-layout -t "$SESSION_NAME:$window_name" tiled
    done
fi

echo ""
echo -e "${GREEN}=== Fuzzing setup complete! ===${NC}"
echo -e "${BLUE}Session: $SESSION_NAME${NC}"
echo ""
echo "Commands:"
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
