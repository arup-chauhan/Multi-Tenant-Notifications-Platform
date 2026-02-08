# k6 Tests

Implemented suites:

1. HTTP submit steady-state load: `steady_state.js`
2. WebSocket concurrent connection fan-out: `websocket_fanout.js`
3. Burst/spike scenario: `burst_spike.js`
4. Reconnect storm scenario: `reconnect_storm.js`
5. Slow consumer and backpressure scenario: `slow_consumer.js`
6. Single-request smoke check: `smoke_submit.js`

Store result artifacts in `platform/tests/load/k6/results/`.
