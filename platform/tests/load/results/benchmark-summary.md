# Benchmark Summary

Measured performance baselines for the MTNP stack.

## Run Metadata

- Date: `2026-02-09T03:35:19Z`
- Environment: `Codex workspace sandbox + Docker Desktop`
- Stack: `platform/infra/docker-compose.local.yml` (gateway + dispatcher + storage + Redis + Cassandra)
- Execution mode: Docker-network tests against `multi-tenant-notification-platfrom_default` / `mtnp-gateway:8080`

## k6 Results (HTTP + WebSocket)

- `smoke_submit.ts`
  - Checks pass: `100%` (1/1)
  - HTTP p95: `17.59ms`
  - Errors: `0%`
  - Artifact: `platform/tests/load/k6/results/smoke_submit_summary.json`

- `steady_state.ts` (20 VUs, 5m)
  - Checks pass: `100%` (29,225/29,225)
  - Throughput: `97.39 req/s` (`29,225` requests)
  - HTTP p95: `12.36ms`
  - Errors: `0%`
  - Artifact: `platform/tests/load/k6/results/steady_state_summary.json`

- `burst_spike.ts` (10 -> 200 -> 10 VUs)
  - Throughput: `1254.55 req/s` (`112,936` requests)
  - HTTP p95: `195.69ms`
  - Errors: `39.21%` (intentional overload profile)
  - Artifact: `platform/tests/load/k6/results/burst_spike_summary.json`

- `websocket_fanout.ts`
  - Handshake success (`101`): `100%` (600/600)
  - `ws_connecting` p95: `43.56ms`
  - `ws_session_duration` p95: `10.06s`
  - Artifact: `platform/tests/load/k6/results/websocket_fanout_summary.json`

- `reconnect_storm.ts`
  - Sessions: `3,600` (`39.93 sessions/s`)
  - `ws_connecting` p95: `9.47ms`
  - `ws_session_duration` p95: `2.01s`
  - Artifact: `platform/tests/load/k6/results/reconnect_storm_summary.json`

- `slow_consumer.ts`
  - Sessions: `200`
  - `ws_connecting` p95: `7.01ms`
  - `ws_session_duration` p95: `15.01s`
  - Artifact: `platform/tests/load/k6/results/slow_consumer_summary.json`

## wrk Results (HTTP Throughput)

- Execution mode: `wrk` installed and executed inside `mtnp-gateway` container.

- `health_check.lua` (10s, 2 threads, 20 connections)
  - Requests/sec: `11934.29`
  - Latency avg: `2.32ms`
  - Latency p99: `17.86ms`
  - Artifact: `platform/tests/load/wrk/results/health_check.txt`

- `post_notifications.lua` (60s, 8 threads, 200 connections)
  - Requests/sec: `1010.60`
  - Latency avg: `148.85ms`
  - Latency p99: `566.63ms`
  - Non-2xx/3xx: `7202`
  - Socket timeouts: `6`
  - Artifact: `platform/tests/load/wrk/results/post_notifications.txt`

- `post_notifications_auth.lua` (60s, 8 threads, 200 connections)
  - Requests/sec: `1048.23`
  - Latency avg: `154.27ms`
  - Latency p99: `671.05ms`
  - Non-2xx/3xx: `2519`
  - Artifact: `platform/tests/load/wrk/results/post_notifications_auth.txt`

## Reliability Signals Observed

- Steady-state run: no request failures under sustained 20 VU load.
- Burst run: controlled overload reproduced (expected non-2xx when pressure spikes).
- WebSocket fanout/reconnect/slow-consumer scenarios completed without handshake failures.

## Notes

- Use `bash platform/tests/load/k6/run_local.sh` for portable k6 runs.
- Use `bash platform/tests/load/wrk/run_local.sh` on a native host setup where `wrk` is runnable.
