# JWT verification routed by algorithm: HS256 local, RS256/ES256 local-or-JWKS

JWT validation routes on the token's algorithm. HS256 (symmetric) always verifies against the local `JWT_SECRET`. RS256/ES256 (asymmetric) verify against a configured local public key or a remote `JWKS_URI`, fetched lazily on first use. This avoids config ambiguity — there is no mode where "is the secret local or remote?" is undefined — and keeps symmetric tokens working even if a JWKS endpoint is unreachable.

## Consequences

- Supports both self-signed (HS256) and IdP-issued (RS/ES + JWKS) deployments without a mode switch.
- A JWKS outage degrades only asymmetric verification, not the whole gateway.
