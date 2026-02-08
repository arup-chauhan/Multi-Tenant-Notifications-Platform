# k6 Tests

Implemented suites:

1. HTTP submit steady-state load: `steady_state.ts`
2. WebSocket concurrent connection fan-out: `websocket_fanout.ts`
3. Burst/spike scenario: `burst_spike.ts`
4. Reconnect storm scenario: `reconnect_storm.ts`
5. Slow consumer and backpressure scenario: `slow_consumer.ts`
6. Single-request smoke check: `smoke_submit.ts`

Store result artifacts in `platform/tests/load/k6/results/`.

Quick run:

```bash
k6 run platform/tests/load/k6/smoke_submit.ts
k6 run platform/tests/load/k6/steady_state.ts
```

Full local run helper:

```bash
bash platform/tests/load/k6/run_local.sh
```

Companion HTTP baseline tool:

- Use `platform/tests/load/wrk/` when you want raw ingress saturation numbers.
