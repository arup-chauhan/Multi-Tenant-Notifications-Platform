#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT_DIR/jwt_helpers.sh"

GATEWAY_HTTP_BASE="${GATEWAY_HTTP_BASE:-http://127.0.0.1:8080}"
GATEWAY_WS_URL="${GATEWAY_WS_URL:-ws://127.0.0.1:8080/ws}"
JWT_HS256_SECRET="${JWT_HS256_SECRET:-}"
TENANT_ID="${TENANT_ID:-tenant-e2e}"
WRONG_TENANT_ID="${WRONG_TENANT_ID:-tenant-other}"
USER_ID="${USER_ID:-user-e2e}"

if [[ -z "$JWT_HS256_SECRET" ]]; then
  echo "[auth-negative] JWT_HS256_SECRET is required"
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[auth-negative] missing command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd openssl
require_cmd k6

post_with_token() {
  local token="$1"
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GATEWAY_HTTP_BASE/v1/notifications" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"user_id\":\"$USER_ID\",\"channel\":\"alerts\",\"content\":\"auth-negative\"}"
}

now="$(date +%s)"

expired_token="$(build_hs256_jwt "$TENANT_ID" "$USER_ID" "$((now - 600))" "$((now - 600))" "$((now - 300))" "$JWT_HS256_SECRET")"
expired_status="$(post_with_token "$expired_token")"
if [[ "$expired_status" != "401" ]]; then
  echo "[auth-negative] expected 401 for expired token, got $expired_status"
  exit 1
fi
echo "[auth-negative] expired token correctly rejected"

future_token="$(build_hs256_jwt "$TENANT_ID" "$USER_ID" "$((now + 600))" "$((now + 600))" "$((now + 1200))" "$JWT_HS256_SECRET")"
future_status="$(post_with_token "$future_token")"
if [[ "$future_status" != "401" ]]; then
  echo "[auth-negative] expected 401 for not-yet-valid token, got $future_status"
  exit 1
fi
echo "[auth-negative] not-yet-valid token correctly rejected"

valid_token="$(build_hs256_jwt "$TENANT_ID" "$USER_ID" "$((now - 60))" "$((now - 60))" "$((now + 300))" "$JWT_HS256_SECRET")"
echo "[auth-negative] verifying websocket tenant mismatch rejection"
k6 run \
  --quiet \
  --env E2E_GATEWAY_WS_URL="$GATEWAY_WS_URL" \
  --env E2E_BEARER_TOKEN="$valid_token" \
  --env E2E_TENANT_ID="$TENANT_ID" \
  --env E2E_WRONG_TENANT_ID="$WRONG_TENANT_ID" \
  --env E2E_CHANNEL="alerts" \
  "$ROOT_DIR/ws_tenant_mismatch_e2e.ts"

echo "[auth-negative] checks passed"
