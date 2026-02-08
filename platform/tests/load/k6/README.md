# k6 Tests

Implemented suites:

1. HTTP submit steady-state load: `steady_state.js`
2. WebSocket concurrent connection fan-out: `websocket_fanout.js`
3. Burst/spike scenario: `burst_spike.js`
4. Reconnect storm scenario: `reconnect_storm.js`
5. Slow consumer and backpressure scenario: `slow_consumer.js`
6. Single-request smoke check: `smoke_submit.js`

Store result artifacts in `platform/tests/load/k6/results/`.

Quick run:

```bash
k6 run platform/tests/load/k6/smoke_submit.js
k6 run platform/tests/load/k6/steady_state.js
```

Full local run helper:

```bash
bash platform/tests/load/k6/run_local.sh
```

Companion HTTP baseline tool:

- Use `platform/tests/load/wrk/` when you want raw ingress saturation numbers.
