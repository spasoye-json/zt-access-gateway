# Casbin policy evaluation fails closed

Any error from the Casbin enforcer — at startup or at request time — results in a **DENY** (`policy_error`), an emitted event, and an incremented error counter; it never falls through to ALLOW. This is explicit because Casbin's own default behaviour on an enforcer error can leave traffic unfiltered, which for an authorization gateway is the worst possible failure mode: a policy bug would silently bypass all access control.

Mechanics: [HARDENING_ARCHITECTURE.md §10](../HARDENING_ARCHITECTURE.md#10-dynamic-threat-escalation).

## Consequences

- A malformed `policy.csv` or `model.conf` makes the gateway deny rather than allow — operators discover misconfiguration immediately, not after a breach.
- `PolicyEvaluatorService.evaluate` is total: it returns a Decision and never throws into the pipeline.
