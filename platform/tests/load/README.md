# Load Testing

This directory contains two complementary test stacks:

1. `k6/` for scenario-driven HTTP and WebSocket load tests.
2. `wrk/` for raw HTTP throughput and latency baseline tests.

Use the unified runner:

```bash
bash platform/tests/load/run_all.sh
```

Run suites individually:

```bash
bash platform/tests/load/k6/run_local.sh
bash platform/tests/load/wrk/run_local.sh
```
