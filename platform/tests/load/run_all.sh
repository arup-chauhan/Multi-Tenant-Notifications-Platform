#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v k6 >/dev/null 2>&1; then
  echo "[load] k6 is not installed. Install k6 to run scenario tests."
  exit 1
fi

if ! command -v wrk >/dev/null 2>&1; then
  echo "[load] wrk is not installed. Install wrk to run HTTP baseline tests."
  exit 1
fi

echo "[load] Starting k6 suite (HTTP + WebSocket)"
bash "$ROOT_DIR/k6/run_local.sh"

echo "[load] Starting wrk suite (HTTP baseline)"
bash "$ROOT_DIR/wrk/run_local.sh"

echo "[load] Completed all load suites."
