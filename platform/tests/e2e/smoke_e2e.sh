#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/../../.." && pwd)"
source "$ROOT_DIR/jwt_helpers.sh"

GATEWAY_HTTP_BASE="${GATEWAY_HTTP_BASE:-http://127.0.0.1:8080}"
GATEWAY_WS_URL="${GATEWAY_WS_URL:-ws://127.0.0.1:8080/ws}"
STORAGE_HTTP_BASE="${STORAGE_HTTP_BASE:-http://127.0.0.1:8090}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_STREAM_NAME="${REDIS_STREAM_NAME:-notifications_stream}"
CASSANDRA_HOST="${CASSANDRA_HOST:-127.0.0.1}"
CASSANDRA_PORT="${CASSANDRA_PORT:-9042}"
CASSANDRA_KEYSPACE="${CASSANDRA_KEYSPACE:-notification_platform}"
CASSANDRA_CONTAINER_NAME="${CASSANDRA_CONTAINER_NAME:-mtnp-cassandra}"
TENANT_ID="${TENANT_ID:-tenant-e2e}"
USER_ID="${USER_ID:-user-e2e}"
CHANNEL="${CHANNEL:-alerts}"
JWT_HS256_SECRET="${JWT_HS256_SECRET:-}"
E2E_BEARER_TOKEN="${E2E_BEARER_TOKEN:-}"
E2E_JWT_TTL_SECONDS="${E2E_JWT_TTL_SECONDS:-300}"

MARKER="smoke-$(date +%s)-$RANDOM"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[e2e] missing command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd redis-cli
require_cmd k6

if ! command -v cqlsh >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
  echo "[e2e] missing command: need either cqlsh or docker for Cassandra verification"
  exit 1
fi

cassandra_query() {
  local cql="$1"
  if command -v cqlsh >/dev/null 2>&1; then
    cqlsh "$CASSANDRA_HOST" "$CASSANDRA_PORT" -e "$cql" 2>/dev/null || true
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    docker exec "$CASSANDRA_CONTAINER_NAME" cqlsh "$CASSANDRA_HOST" "$CASSANDRA_PORT" -e "$cql" 2>/dev/null || true
    return 0
  fi
  echo ""
}

if [[ -z "$E2E_BEARER_TOKEN" && -n "$JWT_HS256_SECRET" ]]; then
  require_cmd openssl
  now="$(date +%s)"
  iat="$now"
  nbf="$((now - 5))"
  exp="$((now + E2E_JWT_TTL_SECONDS))"
  E2E_BEARER_TOKEN="$(build_hs256_jwt "$TENANT_ID" "$USER_ID" "$iat" "$nbf" "$exp" "$JWT_HS256_SECRET")"
  echo "[e2e] generated HS256 bearer token for tenant=$TENANT_ID"
fi

echo "[e2e] checking service health endpoints"
curl -fsS "$GATEWAY_HTTP_BASE/health" >/dev/null
curl -fsS "$STORAGE_HTTP_BASE/health" >/dev/null

echo "[e2e] running websocket delivery test via k6 (marker=$MARKER)"
k6 run \
  --quiet \
  --env E2E_GATEWAY_HTTP_BASE="$GATEWAY_HTTP_BASE" \
  --env E2E_GATEWAY_WS_URL="$GATEWAY_WS_URL" \
  --env E2E_TENANT_ID="$TENANT_ID" \
  --env E2E_USER_ID="$USER_ID" \
  --env E2E_CHANNEL="$CHANNEL" \
  --env E2E_MARKER="$MARKER" \
  --env E2E_BEARER_TOKEN="$E2E_BEARER_TOKEN" \
  "$ROOT_DIR/ws_delivery_e2e.ts"

echo "[e2e] verifying stream entry in Redis"
LATEST="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw XREVRANGE "$REDIS_STREAM_NAME" + - COUNT 1)"
LATEST_ID="$(echo "$LATEST" | head -n 1)"
if [[ -z "$LATEST_ID" ]]; then
  echo "[e2e] no stream entries found in $REDIS_STREAM_NAME"
  exit 1
fi
if ! echo "$LATEST" | grep -q "e2e-$MARKER"; then
  echo "[e2e] latest stream event does not contain expected marker e2e-$MARKER"
  exit 1
fi

echo "[e2e] latest stream id=$LATEST_ID; polling Cassandra for delivery rows"
for _ in $(seq 1 20); do
  CQL="SELECT status, content FROM $CASSANDRA_KEYSPACE.delivery_status WHERE tenant_id='$TENANT_ID' AND notification_id='$LATEST_ID';"
  RESULT="$(cassandra_query "$CQL")"
  if echo "$RESULT" | grep -q "e2e-$MARKER"; then
    echo "[e2e] Cassandra persistence verified for notification_id=$LATEST_ID"
    echo "[e2e] smoke test passed"
    exit 0
  fi
  sleep 1
done

echo "[e2e] Cassandra row not observed for notification_id=$LATEST_ID"
exit 1
