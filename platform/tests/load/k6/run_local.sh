#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT_DIR="$ROOT_DIR/results"
mkdir -p "$RESULT_DIR"

echo "[k6] Running smoke_submit.js"
k6 run --out json="$RESULT_DIR/smoke_submit.json" "$ROOT_DIR/smoke_submit.js"

echo "[k6] Running steady_state.js"
k6 run --out json="$RESULT_DIR/steady_state.json" "$ROOT_DIR/steady_state.js"

echo "[k6] Running burst_spike.js"
k6 run --out json="$RESULT_DIR/burst_spike.json" "$ROOT_DIR/burst_spike.js"

echo "[k6] Completed. Results in $RESULT_DIR"
