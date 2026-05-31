# Fixed, non-configurable fail-fast pipeline order

Every request runs through one fixed sequence — JA4H → blacklist → rate limit → honeypot → auth → revocation → trust → hashcash → policy → MFA → proxy → BOPLA → audit — with no per-route reordering or pluggable slot registry. The order is load-bearing: cheap rejections (blacklist, honeypot) happen before expensive work, and later stages read context populated by earlier ones (policy reads the trust score; audit fires after the policy decision). Making it configurable would invite ordering bugs that silently break these invariants (e.g. auditing before a decision exists, or scoring an unauthenticated request).

Mechanics: [HARDENING_ARCHITECTURE.md §2](../HARDENING_ARCHITECTURE.md#2-fail-fast-pipeline). Stage abstraction: [CONTEXT.md](../../CONTEXT.md) ("Stage", "StageContext").

## Consequences

- Adding a stage means inserting it at the correct, reasoned position in code — not configuration.
- The order is a tested invariant, not an implementation accident.
