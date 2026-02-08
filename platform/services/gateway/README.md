# Gateway Service

Responsibilities:

1. HTTP ingress (`POST /v1/notifications`)
2. Tenant auth context extraction
3. WebSocket connection/session manager
4. Notification fan-out to connected clients
