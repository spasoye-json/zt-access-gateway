# Deliberate scope boundaries (the explicit "no"s)

Several capabilities a reader might expect are intentionally out of scope, to keep the gateway a focused metadata-layer authorization point rather than a platform. Recording the rejections here stops them being re-proposed as oversights.

| Excluded | Why |
|---|---|
| Frontend / admin UI | Doubles attack surface; policy-as-code in CSV is git-auditable. |
| Built-in IdP / OAuth2 / SAML integration | The gateway validates JWTs from any issuer ([ADR-0010](0010-algorithm-routed-jwks.md)); IdP is a separate product. |
| Stateful sessions | Breaks the stateless design ([ADR-0012](0012-stateless-single-instance-design.md)); would require Redis. |
| WebSocket proxying | Orthogonal to per-request ZT policy; complex lifecycle. |
| ML-based anomaly detection | ~5% of the value for ~20× the complexity; heuristic 7-signal scoring covers the risk surface. |
| DLP / payload inspection | Latency + legal risk (PII in logs); out of scope for a metadata-layer gateway. |

## Consequences

- These are revisitable, but only as deliberate scope expansions with their own justification — not bug fixes.
