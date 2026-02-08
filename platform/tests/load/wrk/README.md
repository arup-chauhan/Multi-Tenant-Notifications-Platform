# wrk Tests

Use `wrk` for high-throughput HTTP baseline tests.

## Scripts

1. `health_check.lua` - `GET /health` baseline
2. `post_notifications.lua` - `POST /v1/notifications` baseline
3. `post_notifications_auth.lua` - same ingress test with optional bearer token

## Quick Commands

```bash
wrk -t2 -c20 -d10s -s platform/tests/load/wrk/health_check.lua http://127.0.0.1:8080
wrk -t8 -c200 -d60s -s platform/tests/load/wrk/post_notifications.lua http://127.0.0.1:8080
```

## Auth Variant

```bash
export WRK_BEARER_TOKEN="<token>"
wrk -t8 -c200 -d60s -s platform/tests/load/wrk/post_notifications_auth.lua http://127.0.0.1:8080
```

## Local Runner

```bash
bash platform/tests/load/wrk/run_local.sh
```

Outputs are saved in `platform/tests/load/wrk/results/`.

Tune runtime parameters via environment variables:

```bash
BASE_URL=http://127.0.0.1:8080 DURATION=45s THREADS=8 CONNECTIONS=300 \
  bash platform/tests/load/wrk/run_local.sh
```
