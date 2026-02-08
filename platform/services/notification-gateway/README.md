# Gateway Service

Responsibilities:

1. HTTP ingress (`POST /v1/notifications`)
2. Tenant auth context extraction
3. WebSocket connection/session manager
4. Notification fan-out to connected clients

Implemented ingress endpoints:

1. `POST /v1/notifications`
2. `GET /health`
3. `GET /ws` (WebSocket realtime feed)
4. `POST /v1/internal/deliver` (internal dispatcher -> websocket fan-out path)

Environment variables:

1. `GATEWAY_PORT` (default: `8080`)
2. `REDIS_HOST` (default: `127.0.0.1`)
3. `REDIS_PORT` (default: `6379`)
4. `REDIS_STREAM_NAME` (default: `notifications_stream`)
5. `JWT_HS256_SECRET` (default: empty)

Auth behavior:

1. If `Authorization: Bearer <jwt>` is present on `POST /v1/notifications`, token signature is verified using `HS256` with `JWT_HS256_SECRET`.
2. Invalid bearer tokens are rejected with `401`.
3. If bearer token is not present, `tenant_id` from payload is used as local/dev fallback.

WebSocket subscription behavior:

1. Connect to `GET /ws`.
2. Send text frame: `{"type":"subscribe","tenant_id":"<tenant>","channel":"<channel>"}`.
3. Gateway delivers only messages matching the subscribed `tenant_id` and `channel`.
4. If WS bearer JWT is present, subscription `tenant_id` must match token tenant.
