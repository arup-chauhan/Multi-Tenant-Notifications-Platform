# Architecture

## Goal

Build a multi-tenant, low-latency notification platform with clear reliability semantics and measurable SLOs.

## High-Level Flow

1. Client sends `POST /v1/notifications` to `gateway`.
2. `gateway` validates tenant context and writes envelope to Redis Stream.
3. `dispatcher` consumes from Redis Stream consumer group.
4. `dispatcher` persists notification state to Cassandra via `storage`.
5. `dispatcher` fans out to active WebSocket sessions managed by `gateway`.
6. Failed deliveries are retried; exhausted messages are sent to DLQ.

## Core Design Choices

1. Redis Streams over Pub/Sub for replay, consumer groups, and pending entries tracking.
2. Cassandra for write-heavy, tenant-partitioned NoSQL persistence.
3. C++ service split for isolation:
   - `gateway`: ingress + websocket
   - `dispatcher`: processing + retry orchestration
   - `storage`: persistence contract

## Multi-Tenant Model

1. Every request/event includes `tenant_id`.
2. Tenant-scoped stream keys and Cassandra partition keys.
3. Tenant-specific quota and rate policies.
4. Tenant-level latency and failure metrics.
