#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
DURATION="${DURATION:-30s}"
THREADS="${THREADS:-8}"
CONNECTIONS="${CONNECTIONS:-200}"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT_DIR="$ROOT_DIR/results"
mkdir -p "$RESULT_DIR"

echo "[wrk] health check baseline"
wrk -t2 -c20 -d10s -s "$ROOT_DIR/health_check.lua" "$BASE_URL" | tee "$RESULT_DIR/health_check.txt"

echo "[wrk] notification ingress baseline"
wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" -s "$ROOT_DIR/post_notifications.lua" "$BASE_URL" | tee "$RESULT_DIR/post_notifications.txt"

echo "[wrk] done. results: $RESULT_DIR"
