# Audit before allow (write-ahead log)

An ALLOW decision is blocked until its audit entry is durably persisted; if the write fails after its retries are exhausted, the request is **denied** (503) rather than served unaudited. This is the inverse of the common "log asynchronously, never block the request" pattern, chosen deliberately so there can be no unaudited ALLOW + proxy — the audit trail is a hard security requirement, not best-effort telemetry.

Mechanics: [HARDENING_ARCHITECTURE.md §11](../HARDENING_ARCHITECTURE.md#11-audit-write-ahead-buffer).

## Considered options

- **Async/best-effort audit (rejected):** lowest latency, but a downstream DB hiccup produces silently unaudited access — unacceptable for a zero-trust gateway.
- **Audit after a successful proxy (rejected):** the access has already happened by the time the write fails.

## Consequences

- An audit-store outage degrades the gateway to denying traffic rather than allowing it unrecorded (fail-closed). Audit availability is therefore on the request critical path and must be monitored.
- Audit *failures specific to the WAL exhaustion* deny; unrelated best-effort logging still must never throw into the request path.
