# Runbook

## Local Bootstrap

1. Start infra: Redis + Cassandra via Docker Compose.
2. Build C++ services via CMake.
3. Start `gateway`, `dispatcher`, and `storage`.
4. Run smoke test:
   - `bash platform/tests/e2e/smoke_e2e.sh`
5. Run load validation:
   - `bash platform/tests/load/run_all.sh`

## Operational Checks

1. Consumer lag in Redis Stream group.
2. DLQ growth trend.
3. Delivery p95 and p99 latency.
4. WebSocket active session count.
5. Cassandra write/read timeouts.
6. Retry stream growth and replay drain rate.

## Incident Basics

1. If Redis unavailable:
   - reject new submissions with clear error
   - keep gateway healthy/readiness degraded
2. If Cassandra unavailable:
   - route delivery metadata to retry queue
   - prevent silent drops
3. If gateway node overloaded:
   - apply backpressure/rate limit
   - preserve core delivery workers
