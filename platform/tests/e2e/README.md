# End-to-End Smoke Tests

This folder validates the full notification path:

1. HTTP ingress acceptance (`POST /v1/notifications`)
2. WebSocket delivery fan-out (`GET /ws`)
3. Redis stream write confirmation
4. Cassandra persistence confirmation

Run:

```bash
bash platform/tests/e2e/smoke_e2e.sh
```

Configurable environment variables:

- `GATEWAY_HTTP_BASE` (default `http://127.0.0.1:8080`)
- `GATEWAY_WS_URL` (default `ws://127.0.0.1:8080/ws`)
- `REDIS_HOST` / `REDIS_PORT`
- `REDIS_STREAM_NAME`
- `CASSANDRA_HOST` / `CASSANDRA_PORT` / `CASSANDRA_KEYSPACE`
- `TENANT_ID` / `USER_ID` / `CHANNEL`
