# Security Policy

## Scope

This document defines authentication and tenant-isolation expectations for the Multi-Tenant Notification Platform.

## Authentication Model

Gateway security controls:

1. Bearer JWT verification with `HS256` (`JWT_HS256_SECRET`)
2. Optional strict mode: `GATEWAY_REQUIRE_AUTH=true`
3. Time-claim validation:
   - `exp` is required
   - `nbf` and `iat` are validated
   - skew is controlled by `JWT_CLOCK_SKEW_SECONDS`

## Required JWT Claims

A valid token must include:

1. `tenant_id` (or `tid`)
2. `exp`

Recommended:

1. `sub`
2. `iat`
3. `nbf`

## WebSocket Isolation Rules

1. Client connects to `GET /ws` (with bearer token in strict mode).
2. Client sends subscribe frame:
   - `{"type":"subscribe","tenant_id":"<tenant>","channel":"<channel>"}`
3. Gateway only fan-outs events matching subscribed `tenant_id` + `channel`.
4. If JWT tenant and subscribe `tenant_id` mismatch, gateway closes the connection.

## Operational Hardening

1. Run with `GATEWAY_REQUIRE_AUTH=true` in non-dev environments.
2. Rotate `JWT_HS256_SECRET` periodically.
3. Set short-lived tokens and bounded `JWT_CLOCK_SKEW_SECONDS`.
4. Monitor repeated `401` patterns and websocket close spikes.
5. Run:
   - `bash platform/tests/e2e/run_all.sh`

## Known Limitations

1. Only `HS256` is currently supported.
2. JWT validation uses shared secret model (no JWKS/RS256 path yet).
3. Minimal JSON parsing is used in gateway request handling.
