# Infra

This folder contains local infrastructure definitions for development and testing.

Runtime stack:

1. Redis (Streams)
2. Notification Storage service
3. Notification Dispatcher service
4. Notification Gateway service
5. Cassandra
6. Prometheus + Grafana (deployment extension)

Schema initialization:

1. `platform/infra/cassandra/schema.cql` is applied by `cassandra-init` during local compose startup.

Gateway auth runtime flags:

1. `JWT_HS256_SECRET` sets HS256 verification key.
2. `GATEWAY_REQUIRE_AUTH=true` enforces bearer token requirement on `/v1/notifications` and `/ws`.
