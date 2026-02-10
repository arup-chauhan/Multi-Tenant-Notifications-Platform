#!/usr/bin/env bash
set -euo pipefail

# DLQ Replay Tool
# Replays failed notifications from DLQ back to retry stream
# Note: correlation_id is preserved (stable business ID)
# New trace spans will be created automatically for replay operations

REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DLQ_STREAM_NAME="${REDIS_DLQ_STREAM_NAME:-notifications_dlq_stream}"
TARGET_STREAM="${TARGET_STREAM:-notifications_retry_stream}"
COUNT="${COUNT:-50}"
DELETE_AFTER_REPLAY="${DELETE_AFTER_REPLAY:-false}"

if ! command -v redis-cli >/dev/null 2>&1; then
  echo "[replay-dlq] redis-cli is required"
  exit 1
fi

echo "[replay-dlq] reading up to $COUNT items from $REDIS_DLQ_STREAM_NAME"
IDS="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw XREVRANGE "$REDIS_DLQ_STREAM_NAME" + - COUNT "$COUNT" | awk 'NR%2==1{print $1}')"

if [[ -z "$IDS" ]]; then
  echo "[replay-dlq] no DLQ entries found"
  exit 0
fi

replayed=0
for id in $IDS; do
  entry="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw XRANGE "$REDIS_DLQ_STREAM_NAME" "$id" "$id")"
  if [[ -z "$entry" ]]; then
    continue
  fi
  mapfile -t lines < <(printf '%s\n' "$entry")
  if [[ "${#lines[@]}" -lt 3 ]]; then
    continue
  fi

  args=("XADD" "$TARGET_STREAM" "*")
  # lines[0] is id; remaining are alternating field/value
  for ((i=1; i<${#lines[@]}; i+=2)); do
    key="${lines[$i]}"
    val=""
    if (( i + 1 < ${#lines[@]} )); then
      val="${lines[$((i+1))]}"
    fi
    args+=("$key" "$val")
  done
  redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw "${args[@]}" >/dev/null
  replayed=$((replayed + 1))

  if [[ "$DELETE_AFTER_REPLAY" == "true" ]]; then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --raw XDEL "$REDIS_DLQ_STREAM_NAME" "$id" >/dev/null
  fi
done

echo "[replay-dlq] replayed=$replayed target_stream=$TARGET_STREAM delete_after_replay=$DELETE_AFTER_REPLAY"
