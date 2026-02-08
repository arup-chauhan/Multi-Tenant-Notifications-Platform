# Storage Service

Responsibilities:

1. Cassandra persistence adapter
2. Idempotent writes for notification state
3. Read/query APIs for tenant audit and delivery status

Implemented internal API:

1. `POST /v1/internal/store` for persistence writes
2. `GET /health` for service health

Current persistence mode:

1. Cassandra-backed writes to `delivery_status` table (via `cqlsh` execution)
2. Optional append-only file fallback when Cassandra write fails
3. Record envelope includes tenant, notification id, status, attempt, and error

Environment variables:

1. `STORAGE_PORT` (default: `8090`)
2. `STORAGE_BACKEND` (default: `cassandra`)
3. `STORAGE_FALLBACK_TO_FILE` (default: `true`)
4. `STORAGE_DATA_FILE` (default: `/tmp/notification_storage.log`)
5. `CASSANDRA_HOST` (default: `cassandra`)
6. `CASSANDRA_PORT` (default: `9042`)
7. `CASSANDRA_KEYSPACE` (default: `notification_platform`)
