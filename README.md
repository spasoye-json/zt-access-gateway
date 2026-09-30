# Zero-Trust Access Gateway (NestJS)

A hardened access gateway that enforces zero-trust principles for a set of internal microservices. Every inbound request passes through a fixed, fail-fast pipeline of 13 stages: client fingerprinting, deception, authentication, revocation, behavioral trust scoring, proof-of-work, policy evaluation, MFA step-up, fail-closed audit, mTLS proxying, and response field stripping. No request reaches a downstream service without being verified, scored, and authorized first.

## Documentation

- [`docs/THESIS_PIPELINE.md`](docs/THESIS_PIPELINE.md), the full stage-by-stage pipeline walkthrough.
- [`docs/HARDENING_ARCHITECTURE.md`](docs/HARDENING_ARCHITECTURE.md) and [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md), mechanics and diagrams for each security control.
- [`docs/adr/`](docs/adr/), Architecture Decision Records: the why behind the hard-to-reverse choices.
- [`CONTEXT.md`](CONTEXT.md), the ubiquitous-language glossary for the domain.
- [`docs/STARTUP_GUIDE.md`](docs/STARTUP_GUIDE.md) and [`docs/PRESENTATION_BRIEF.md`](docs/PRESENTATION_BRIEF.md), local setup, the demo environment, and the UAT scenario suite.

## Current Capabilities

| Area | Details |
| --- | --- |
| Fingerprinting | Every request is JA4H-fingerprinted from its HTTP shape (method, version, header names, accept, content-type). The fingerprint keys the deception layer and feeds the trust score. |
| Deception | Honeypot routes (`/.env`, admin paths, and configurable extras) return deceptive bodies with canary values, then terminally blacklist the caller's JA4H fingerprint. Repeat visitors are tarpitted and rejected. |
| Authentication | Bearer JWT verification, algorithm-routed by the token header: HS256 against `JWT_SECRET`, RS256 or ES256 against `JWT_PUBLIC_KEY` (SPKI) or a `JWKS_URI` endpoint. `alg: none` is rejected, `jti`, `sub`, and `deviceId` claims are mandatory, and MFA-typed tokens cannot be used as access tokens. |
| Revocation | `POST /auth/revoke` blacklists a token's `jti` immediately (in-memory, single-instance by design, see ADR-0012). |
| Trust / Risk | A continuous score in [0, 1] built from a 0.5 baseline plus seven signals: terminal JA4H blacklist (forces 1.0), device reputation, IP reputation, request frequency, JA4H drift, behavioral anomaly (hour-of-day and rate baselines), and idle decay. Signal faults raise risk, never lower it. Backed by `trust_signals` and `trust_activity` in Postgres. |
| Proof-of-work | Requests above a trust-score threshold must solve a hashcash challenge (stateless HMAC-signed nonces, difficulty scales with the score, single-use replay defense). |
| Policy | Casbin RBAC (`policy/model.conf`, `policy/policy.csv`) evaluates `subject → resource → action`, layered with score thresholds to return **ALLOW / CHALLENGE / DENY**. Any enforcer error fails closed to DENY. A global threat-escalation ladder tightens thresholds while attack signals accumulate. |
| MFA | CHALLENGE promotes to ALLOW only with a valid MFA token: TOTP-based enrollment and verification, secrets AES-256-GCM encrypted at rest, MFA JWTs signed with a separate secret and bound to a SHA-256(user, device, IP) fingerprint to defeat replay. |
| Audit | ALLOW decisions are fail-closed: the audit row must be durably written to Postgres before the proxy fires, and an audit outage degrades to 503, never to unrecorded access (ADR-0001). CHALLENGE and DENY audits are best-effort. |
| Proxy & mTLS | Forwards allowed traffic over mTLS to services in the `PROXY_SERVICE_REGISTRY` allowlist, injecting `x-user-id`, `x-roles`, `x-trust-score`, and `x-ja4h`. Per-service circuit breaker, bounded retries, and a DNS-rebinding guard that blocks loopback and the cloud metadata address. |
| BOPLA | Response bodies are stripped of fields the caller's role may not see (`policy/field-policy.json`) before leaving the gateway. |
| Observability | Prometheus metrics at `/metrics` (decision counters, per-stage latency histograms, security events). Docker Compose ships Prometheus plus a provisioned Grafana security dashboard. |

## The Pipeline

```
Request
  │ JA4H fingerprint middleware (blacklisted fingerprint → tarpit + 403)
  ▼
 1. public bypass          /health, /metrics
 2. honeypot bypass        trap routes → deception + blacklist
 3. auth                   JWT verification → UserClaims
 4. revocation             revoked jti → 401 token_revoked
 5. auth-only bypass       control plane (/auth/revoke, /mfa/*, /policy/admin, /audit/logs)
 6. trust score            7-signal score in [0, 1]
 7. hashcash               high risk → 429 + PoW challenge
 8. policy                 Casbin + thresholds → ALLOW / CHALLENGE / DENY
 9. MFA promotion          CHALLENGE + valid MFA token → ALLOW, else 401 mfa_required
10. audit (fail-closed)    ALLOW is persisted before proxying, or 503
11. proxy                  mTLS forward to the registered service
12. BOPLA strip            role-based response field removal
13. record trust context   telemetry persisted only after a successful ALLOW
```

The order is fixed and load-bearing (ADR-0005); it is encoded once in `src/gateway/gateway.module.ts`.

## Repository Layout

```
.
├── src/
│   ├── fingerprint/   # JA4H computation + blacklist middleware
│   ├── honeypot/      # Trap routes, deceptive responses, tarpit
│   ├── auth/          # JWT verification, revocation, guards
│   ├── trust-score/   # 7-signal scoring engine + telemetry repository
│   ├── hashcash/      # Stateless PoW challenges + verification
│   ├── policy/        # Casbin evaluator, threat escalation, admin API
│   ├── mfa/           # TOTP enrollment, challenges, fingerprint-bound tokens
│   ├── gateway/       # Pipeline orchestrator + the 13 stages
│   ├── proxy/         # mTLS forwarding, registry, breaker, DNS guard
│   ├── audit/         # Fail-closed WAL for ALLOW, best-effort otherwise
│   ├── metrics/       # Prometheus counters and histograms
│   ├── demo-mfa/      # /demo/mfa-token shortcut, registered only in DEMO_MODE
│   ├── shared/        # mTLS service, TOTP util, request context, filters
│   ├── config/        # Joi-validated typed config
│   └── db/            # pg pool + boot-time SQL migrations
├── microservices/     # Sample mTLS upstreams (orders-service, users-service)
├── policy/            # Casbin model + policy CSV + BOPLA field policy
├── sql/migrations/    # Idempotent DDL, replayed at every boot
├── scripts/           # gen-certs.sh, scenario suite, JWT/TOTP/PoW helpers
├── observability/     # Prometheus config + provisioned Grafana dashboard
├── tests/             # Integration and e2e suites (real Postgres)
├── docker-compose.yml         # Full stack
└── docker-compose.demo.yml    # Demo overlay (see PRESENTATION_BRIEF.md)
```

## Getting Started

### Prerequisites

- Node.js 18+
- Docker and Docker Compose (for the full stack and integration tests)

### Install and configure

```bash
npm install
cp .env.example .env   # then fill in real values
```

The gateway validates its configuration at boot with Joi and refuses to start if anything required is missing; every violation is reported at once. Key variables (see `.env.example` for the full annotated list):

| Variable | Description |
| --- | --- |
| `PORT` | Gateway HTTP port (default `3000`). |
| `DATABASE_URL` | Postgres connection string. **Required**: migrations run at boot and the app will not start without a reachable database. |
| `JWT_SECRET` | HS256 secret, minimum 32 chars. Optional `JWT_PUBLIC_KEY` or `JWKS_URI` enable RS256 and ES256; the verifier routes by the token's algorithm, there is no algorithm setting. |
| `HASHCASH_HMAC_SECRET` | Secret for PoW challenge signing, minimum 32 chars, must differ from the JWT secrets. |
| `HASHCASH_TRIGGER_THRESHOLD` | Trust score above which PoW is required (default `0.7`, strict greater-than). |
| `HASHCASH_DIFFICULTY_MIN` / `MAX` | Leading-zero bits required (production `18/22`; the demo uses `8/12`). |
| `POLICY_CHALLENGE_THRESHOLD` / `POLICY_DENY_THRESHOLD` | Score thresholds for CHALLENGE and DENY (defaults `0.5` and `0.8`, and the demo uses `0.7` and `0.9`). |
| `MFA_JWT_SECRET` | Secret for MFA tokens, separate from `JWT_SECRET` (ADR-0006). |
| `MFA_TOTP_ENCRYPTION_KEY` | Base64 key that must decode to exactly 32 bytes (AES-256-GCM for TOTP secrets at rest). |
| `MFA_CHALLENGE_TTL_MS` / `MFA_TOKEN_TTL_MS` | Challenge TTL must be strictly less than token TTL. |
| `MTLS_CA_CERT_PATH` / `MTLS_CLIENT_CERT_PATH` / `MTLS_CLIENT_KEY_PATH` | Gateway certificate material for outbound mTLS. |
| `MTLS_ALLOWED_SUBJECTS` | Comma-separated CN allowlist for downstream server certificates. |
| `PROXY_SERVICE_REGISTRY` | **Required** JSON map of `serviceName → baseUrl`. This is the egress allowlist: only registered services can be proxied to. |
| `PROXY_CB_VOLUME_THRESHOLD` / `PROXY_CB_ERROR_THRESHOLD` / `PROXY_CB_RESET_TIMEOUT` / `PROXY_MAX_RETRIES` | Circuit breaker and retry tuning. |
| `BLACKLIST_TTL_MS` / `HONEYPOT_ROUTES` | Honeypot blacklist TTL and optional extra trap routes. |
| `TRUST_*` | Trust-signal tuning: reputation threshold, decay time constant, anomaly warm-up, frequency window. |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS`, `CORS_ORIGIN` | Edge rate limiting and CORS. |

### Run

```bash
npm run start:dev     # hot reload; needs Postgres reachable at DATABASE_URL
```

### Docker Compose

The full stack (gateway, orders-service, Postgres, Prometheus, Grafana, plus a one-shot cert-mint container):

```bash
docker compose up --build
```

- Gateway: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001` (admin, `GRAFANA_ADMIN_PASSWORD`, default `admin`)
- Postgres: `localhost:5432`

For the deterministic demo environment (pinnable trust scores, fast PoW, a second upstream for BOPLA, and the six-scenario UAT suite), use the demo overlay described in [`docs/PRESENTATION_BRIEF.md`](docs/PRESENTATION_BRIEF.md):

```bash
bash scripts/gen-certs.sh
docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env.demo up --build -d
for n in 1 2 3 4 5 6; do bash scripts/scenarios/scenario-$n.sh; done
```

## Testing

```bash
npm test              # unit suites under src/**/__tests__ (no database needed)
npm run test:e2e      # integration suites under tests/ (needs Postgres; DB suites skip without DATABASE_URL)
npm run test:cov      # coverage report
```

- Unit tests are colocated with each module and mock the repositories.
- Integration tests use a real Postgres (the Compose `postgres` service works) and real libraries: jose, casbin, https servers with actual mTLS handshakes.
- The six UAT scenarios in `scripts/scenarios/` run against the live demo stack and exit non-zero on any mismatch; between them they exercise every pipeline stage.

## Policy Administration API

Admin-role operators can manage rules and threat escalation at runtime:

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/policy/admin/rules` | List loaded Casbin policies. |
| `POST` | `/policy/admin/rules` | Add a policy binding `{ subject, resource, action }`. |
| `DELETE` | `/policy/admin/rules` | Remove a policy binding. |
| `GET` | `/policy/admin/escalation` | Current threat level and counters. |
| `POST` | `/policy/admin/escalation` | Manually override the threat level. |
| `DELETE` | `/policy/admin/escalation` | Clear a manual override. |

Rule changes are persisted through the Casbin adapter and survive restarts.

## Known Boundaries (v1)

Deliberate scope decisions, documented in the ADRs rather than hidden:

- Revocation list, honeypot blacklist, used PoW nonces, and threat-escalation counters are in-memory and single-instance; a shared store (Redis) is the v2 path (ADR-0012).
- The DNS-rebinding guard blocks loopback and the cloud metadata endpoint only; RFC1918 targets are intentionally allowed because upstreams live on private networks. Registry path-prefix routing is the primary SSRF control (ADR-0009).
- No retention jobs yet: `trust_activity`, `audit_logs`, and the MFA tables grow unbounded; expiry is enforced at read time.
- Downstream identity headers are plaintext and rely on network isolation plus mTLS; signed headers are future work.

## License

MIT
