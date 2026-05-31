# Stateless hashcash challenge via HMAC, no database

A hashcash challenge nonce embeds its payload (identity, timestamp, required difficulty) signed with an HMAC secret; verification recomputes the HMAC with no database round-trip. Replay within the short TTL is bounded by an in-memory used-nonce store. We chose this over a `hashcash_challenges` table to keep the hot path free of DB I/O and to add no new dependency, consistent with the rest of the trust pipeline.

Mechanics: [HARDENING_ARCHITECTURE.md §4](../HARDENING_ARCHITECTURE.md#4-hashcash-proof-of-work).

## Consequences

- **Cross-instance replay is not prevented** — the used-nonce store is per-process. Acceptable for the single-instance v1 design ([ADR-0012](0012-stateless-single-instance-design.md)); a multi-instance deployment would need a shared store.
- Challenges are also identity-bound, so a valid solution from one user/device cannot be replayed by another.
