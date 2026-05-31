# Separate signing secret for MFA tokens

MFA tokens are signed with `MFA_JWT_SECRET`, distinct from the `JWT_SECRET` used for session/identity JWTs. The two token types defend different things; sharing one secret means a compromise or rotation of one breaks the other. Bootstrap validation enforces a minimum secret length on both.

## Consequences

- Secrets can be rotated independently.
- A leaked session secret cannot forge MFA promotions, and vice versa.

Related: [ADR-0003](0003-mfa-token-fingerprint-binding.md) (what the MFA token binds to).
