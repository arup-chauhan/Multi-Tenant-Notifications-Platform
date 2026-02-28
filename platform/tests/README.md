# Tests

This is the consolidated test guide for MTNP.

## Structure

1. `platform/tests/e2e/` - end-to-end validation scripts
2. `platform/tests/load/` - load and stress testing scripts
3. `platform/tests/load/results/` - benchmark summaries

## E2E Tests

Run smoke path:

```bash
bash platform/tests/e2e/smoke_e2e.sh
```

Run idempotency path:

```bash
bash platform/tests/e2e/idempotency_e2e.sh
```

Run full E2E suite:

```bash
bash platform/tests/e2e/run_all.sh
```

Run auth negative checks only:

```bash
bash platform/tests/e2e/auth_negative_checks.sh
```

E2E validates:

1. `POST /v1/notifications` acceptance
2. `GET /ws` websocket delivery flow
3. Redis stream write visibility
4. Cassandra persistence visibility

Key E2E env vars:

1. `GATEWAY_HTTP_BASE` (default `http://127.0.0.1:8080`)
2. `GATEWAY_WS_URL` (default `ws://127.0.0.1:8080/ws`)
3. `STORAGE_HTTP_BASE` (default `http://127.0.0.1:8090`)
4. `REDIS_HOST` / `REDIS_PORT` / `REDIS_STREAM_NAME`
5. `CASSANDRA_HOST` / `CASSANDRA_PORT` / `CASSANDRA_KEYSPACE`
6. `TENANT_ID` / `USER_ID` / `CHANNEL`
7. `JWT_HS256_SECRET` / `E2E_BEARER_TOKEN` / `E2E_JWT_TTL_SECONDS`

## Load Tests

Run all load suites:

```bash
bash platform/tests/load/run_all.sh
```

Run k6 suite:

```bash
bash platform/tests/load/k6/run_local.sh
```

Run k6 HTTP-only:

```bash
HTTP_ONLY=true bash platform/tests/load/k6/run_local.sh
```

Run wrk suite:

```bash
bash platform/tests/load/wrk/run_local.sh
```

Artifacts:

1. k6 outputs: `platform/tests/load/k6/results/`
2. wrk outputs: `platform/tests/load/wrk/results/`
3. summary: `platform/tests/load/results/benchmark-summary.md`
