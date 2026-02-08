# Storage Service

Responsibilities:

1. Cassandra persistence adapter
2. Idempotent writes for notification state
3. Read/query APIs for tenant audit and delivery status

Implemented internal API:

1. `POST /v1/internal/store` for persistence writes
2. `GET /health` for service health

Current persistence mode:

1. Append-only durable local log file (`STORAGE_DATA_FILE`)
2. Record envelope includes tenant, notification id, status, attempt, and error

Environment variables:

1. `STORAGE_PORT` (default: `8090`)
2. `STORAGE_DATA_FILE` (default: `/tmp/notification_storage.log`)
