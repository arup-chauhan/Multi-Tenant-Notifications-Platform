# Multi-Tenant Notification Platform

This repository is a production-style, C++-first distributed notification platform.

## Current Status

- New platform structure for C++ services, infra, tests, and docs is created under `platform/`.
- Architecture, known gaps, and execution tasks are tracked in dedicated files.

## Repository Layout

```text
.
├── docs/
│   ├── architecture.md
│   └── runbook.md
├── platform/
│   ├── CMakeLists.txt
│   ├── common/
│   ├── infra/
│   ├── services/
│   │   ├── gateway/
│   │   ├── dispatcher/
│   │   └── storage/
│   └── tests/
│       └── k6/
├── GAPS.md
└── TODO.md
```

## Target Architecture

1. `gateway` (C++ WebSocket + HTTP ingress)
2. `dispatcher` (stream consumer, retry, DLQ, fan-out orchestration)
3. `storage` (notification persistence and query API)
4. `redis streams` for event routing
5. `cassandra` for NoSQL persistence and tenant-scoped data

## Migration Plan

1. Build minimal vertical slice in C++:
   - accept HTTP submit
   - write to Redis stream
   - consume and persist in Cassandra
   - deliver via WebSocket
2. Add multi-tenant controls:
   - tenant-scoped auth context
   - tenant quotas/rate limits
   - tenant-level metrics and alerts
3. Add reproducible load tests and publish results.

## Next Actions

- See `GAPS.md` for architecture/implementation gaps.
- See `TODO.md` for prioritized execution tasks.
