#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$ROOT_DIR/jwt_helpers.sh"

GATEWAY_HTTP_BASE="${GATEWAY_HTTP_BASE:-http://127.0.0.1:8080}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_STREAM_NAME="${REDIS_STREAM_NAME:-notifications_stream}"
TENANT_ID="${TENANT_ID:-tenant-e2e}"
USER_ID="${USER_ID:-user-e2e}"
CHANNEL="${CHANNEL:-alerts}"
JWT_HS256_SECRET="${JWT_HS256_SECRET:-}"
E2E_BEARER_TOKEN="${E2E_BEARER_TOKEN:-}"
E2E_JWT_TTL_SECONDS="${E2E_JWT_TTL_SECONDS:-300}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[e2e-idempotency] missing command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd redis-cli

if [[ -z "$E2E_BEARER_TOKEN" && -n "$JWT_HS256_SECRET" ]]; then
  require_cmd openssl
  now="$(date +%s)"
  iat="$now"
  nbf="$((now - 5))"
  exp="$((now + E2E_JWT_TTL_SECONDS))"
  E2E_BEARER_TOKEN="$(build_hs256_jwt "$TENANT_ID" "$USER_ID" "$iat" "$nbf" "$exp" "$JWT_HS256_SECRET")"
  echo "[e2e-idempotency] generated HS256 bearer token for tenant=$TENANT_ID"
fi

marker="idempotency-$(date +%s)-$RANDOM"
idempotency_key="ik-$marker"
payload="{\"tenant_id\":\"$TENANT_ID\",\"user_id\":\"$USER_ID\",\"channel\":\"$CHANNEL\",\"content\":\"e2e-$marker\"}"

headers=(-H "Content-Type: application/json" -H "Idempotency-Key: $idempotency_key")
if [[ -n "$E2E_BEARER_TOKEN" ]]; then
  headers+=(-H "Authorization: Bearer $E2E_BEARER_TOKEN")
fi

echo "[e2e-idempotency] checking gateway health"
curl -fsS "$GATEWAY_HTTP_BASE/health" >/dev/null

echo "[e2e-idempotency] submitting first request"
resp1="$(curl -sS -w '\n%{http_code}' "${headers[@]}" -d "$payload" \
  "$GATEWAY_HTTP_BASE/v1/notifications")"
body1="$(echo "$resp1" | sed '$d')"
code1="$(echo "$resp1" | tail -n 1)"
if [[ "$code1" != "202" ]]; then
  echo "[e2e-idempotency] first request failed: status=$code1 body=$body1"
  exit 1
fi
if ! echo "$body1" | grep -q '"status":"accepted"'; then
  echo "[e2e-idempotency] unexpected first response body: $body1"
  exit 1
fi

echo "[e2e-idempotency] submitting duplicate request with same idempotency key"
resp2="$(curl -sS -w '\n%{http_code}' "${headers[@]}" -d "$payload" \
  "$GATEWAY_HTTP_BASE/v1/notifications")"
body2="$(echo "$resp2" | sed '$d')"
code2="$(echo "$resp2" | tail -n 1)"
if [[ "$code2" != "202" ]]; then
  echo "[e2e-idempotency] duplicate request failed: status=$code2 body=$body2"
  exit 1
fi
if ! echo "$body2" | grep -q '"deduplicated":true'; then
  echo "[e2e-idempotency] duplicate response missing dedup marker: $body2"
  exit 1
fi

echo "[e2e-idempotency] verifying only one stream entry exists for marker=$marker"
count="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw XREVRANGE "$REDIS_STREAM_NAME" + - COUNT 2000 | grep -c "e2e-$marker" || true)"
if [[ "$count" != "1" ]]; then
  echo "[e2e-idempotency] expected exactly 1 stream entry for marker, found $count"
  exit 1
fi

echo "[e2e-idempotency] idempotency test passed"
