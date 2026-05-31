# Architecture Decision Records

Each ADR records a decision that is **hard to reverse**, **surprising without context**, and **the result of a real trade-off**. Mechanics live in [`HARDENING_ARCHITECTURE.md`](../HARDENING_ARCHITECTURE.md); domain vocabulary in [`CONTEXT.md`](../../CONTEXT.md). ADRs capture the *why*, not the *how*.

| # | Decision |
|---|---|
| [0001](0001-audit-before-allow-wal.md) | Audit before allow (write-ahead log) |
| [0002](0002-trust-signals-persisted-only-on-allow.md) | Trust signal history persisted only after a successful ALLOW |
| [0003](0003-mfa-token-fingerprint-binding.md) | MFA token bound to userId \| deviceId \| ip — not geo or user-agent |
| [0004](0004-casbin-fails-closed.md) | Casbin policy evaluation fails closed |
| [0005](0005-fixed-fail-fast-pipeline.md) | Fixed, non-configurable fail-fast pipeline order |
| [0006](0006-separate-mfa-jwt-secret.md) | Separate signing secret for MFA tokens |
| [0007](0007-stateless-hashcash-nonce.md) | Stateless hashcash challenge via HMAC, no database |
| [0008](0008-opossum-wraps-full-retry-loop.md) | Circuit breaker wraps the full retry loop, not individual attempts |
| [0009](0009-path-prefix-service-routing.md) | Proxy target chosen by path prefix, validated against the service registry |
| [0010](0010-algorithm-routed-jwks.md) | JWT verification routed by algorithm (HS256 local, RS/ES local-or-JWKS) |
| [0011](0011-raw-pg-no-orm.md) | Raw `pg` driver, no ORM |
| [0012](0012-stateless-single-instance-design.md) | Stateless, single-instance design for v1 |
| [0013](0013-deliberate-scope-boundaries.md) | Deliberate scope boundaries (the explicit "no"s) |

New ADRs: take the next sequential number; keep them short.
