# Stateless, single-instance design for v1 — no server sessions, no Redis

The gateway holds no server-side session state: identity is carried by stateless JWTs, and the only shared persistent state lives in Postgres. Some in-process state (hashcash used-nonces, fingerprint blacklist, threat-escalation counters) is intentionally per-instance. v1 targets a single instance; horizontal scaling and a shared (e.g. Redis-backed) state tier are explicitly deferred to v2.

## Consequences

- Per-instance state means features like cross-instance hashcash replay protection ([ADR-0007](0007-stateless-hashcash-nonce.md)) are not yet multi-instance safe — a known, accepted v1 limitation.
- No session store to operate or secure; restart loses only soft in-memory counters, not identity.
- Going multi-instance is a deliberate future project, not an incremental config change.
