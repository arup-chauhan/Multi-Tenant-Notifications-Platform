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
