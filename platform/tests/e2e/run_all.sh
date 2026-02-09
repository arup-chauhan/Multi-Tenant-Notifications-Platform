#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[e2e] Running smoke path checks"
bash "$ROOT_DIR/smoke_e2e.sh"

if [[ -n "${JWT_HS256_SECRET:-}" ]]; then
  echo "[e2e] Running auth negative checks"
  bash "$ROOT_DIR/auth_negative_checks.sh"
else
  echo "[e2e] Skipping auth negative checks (JWT_HS256_SECRET not set)"
fi

echo "[e2e] All configured checks passed"
