# Dispatcher Service

Responsibilities:

1. Consume Redis Streams via consumer groups
2. Retry failed delivery attempts
3. Route exhausted events to DLQ
4. Coordinate storage writes and delivery status updates

Implemented stream behavior:

1. Creates consumer group for main stream (`XGROUP CREATE ... MKSTREAM`)
2. Creates consumer group for retry stream (`XGROUP CREATE ... MKSTREAM`)
3. Reads main + retry streams with `XREADGROUP` and blocking poll
4. ACKs successful deliveries (`XACK`) on the source stream
5. Sends transient failures to retry stream with incremented `retry_count`
6. Sends exhausted retries to DLQ stream and ACKs original source message
7. Persists state transitions through `notification-storage` internal API
8. Pushes successful delivery events to `notification-gateway` internal fan-out endpoint

Environment variables:

1. `REDIS_HOST` (default: `127.0.0.1`)
2. `REDIS_PORT` (default: `6379`)
3. `REDIS_STREAM_NAME` (default: `notifications_stream`)
4. `REDIS_RETRY_STREAM_NAME` (default: `notifications_retry_stream`)
5. `REDIS_DLQ_STREAM_NAME` (default: `notifications_dlq_stream`)
6. `DISPATCHER_GROUP` (default: `notification_dispatcher_group`)
7. `DISPATCHER_CONSUMER` (default: `dispatcher-1`)
8. `DISPATCHER_BLOCK_MS` (default: `5000`)
9. `DISPATCHER_MAX_RETRIES` (default: `3`)
10. `STORAGE_HOST` (default: `127.0.0.1`)
11. `STORAGE_PORT` (default: `8090`)
12. `GATEWAY_HOST` (default: `127.0.0.1`)
13. `GATEWAY_PORT` (default: `8080`)

Testing note:

- Set event field `simulate_fail=true` to force retry/DLQ path.
