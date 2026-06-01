# Zero-Trust Access Gateway — Architecture Whitepaper

This document explains the purpose, architecture, operational model, and developer workflow of the Zero-Trust Access Gateway (ZT-AG). It is written as a text-only whitepaper so it can serve as both onboarding material and the technical appendix for academic review.

---

## 1. Purpose and Scope
- Provide a controllable ingress layer for microservices operating in hostile or untrusted networks.
- Enforce Zero-Trust principles: authenticate every request, continuously assess risk, apply attribute-based policies, and record all actions.
- Offer a reference implementation suitable for research or master’s-level seminars, balancing theoretical rigor with running code.

The repository contains the gateway service, supporting modules (authentication, trust scoring, policy evaluation, proxy, audit, metrics), and sample downstream microservices for demonstrations.

---

## 2. System Goals
1. **Strong Identity** – All requests originate from authenticated users/devices; no implicit trust of network location.
2. **Contextual Authorization** – Policies combine user roles, requested resources, and dynamic risk signals.
3. **Secure Connectivity** – Downstream communication uses mutual TLS with hostname and certificate pinning.
4. **Complete Observability** – Audit logs capture decision rationale; Prometheus metrics expose performance and risk posture.
5. **Operational Practicality** – Configuration is environment-driven, supports certificate rotation, and integrates with CI/testing.

---

## 3. High-Level Architecture
At runtime the gateway stitches together the following NestJS modules:

| Module | Responsibilities | Key Files |
| --- | --- | --- |
| **Bootstrap / AppModule** | Configures Nest app, applies global guards and pipes, wires modules. | `src/main.ts`, `src/app.module.ts`, `src/bootstrap-app.ts` |
| **Auth** | JWT validation, bearer extraction, role capture, guards. | `src/auth/*` |
| **Trust Score** | Telemetry persistence, heuristics for device/IP/frequency scoring. | `src/trust-score/*` |
| **Policy** | Casbin-based authorization, admin APIs. | `src/policy/*` |
| **Proxy** | Service registry, mTLS connection factory, circuit breaker, SSRF defense. | `src/proxy/*`, `src/shared/mtls.service.ts` |
| **Audit** | Persisted decisions with metadata. | `src/audit/*` |
| **Metrics** | Prometheus counters/histograms, `/metrics` endpoint. | `src/metrics/*` |
| **MFA** | Issues/validates challenges when risk requires step-up authentication. | `src/mfa/*` |
| **Gateway Middleware** | End-to-end request orchestration and error handling. | `src/gateway/gateway.middleware.ts` |
| **Sample Microservices** | Demonstration downstream services protected by `GatewayOnlyGuard`. | `microservices/*` |

---

## 4. Component Details

### 4.1 Authentication & Authorization
- `AuthService` verifies JWTs via JOSE: HS algorithms use `JWT_SECRET`; RS/ES use JWKS. Claims are normalized into `UserClaims`.
- `JwtAuthGuard` enforces authentication globally; `@Public()` routes bypass it (e.g., `/` gateway entry point for raw HTTP).
- `RolesGuard` inspects metadata from `@Roles`. Admin-only surfaces include policy admin APIs and metrics.
- Public headers such as `x-device-id` are normalized via `request-context.util.ts` to prevent spoofing attacks.

### 4.2 Trust Scoring
- `TrustScoreService` hybrids behavioral (frequency, IP reputation, device familiarity) and contextual signals. It queries `TrustTelemetryRepository` (Postgres) for historical context.
- Trust activity is persisted for trend analysis and to detect bursts (`countRecentActivity`).
- Scores (0–1) map to qualitative levels low/medium/high; thresholds configurable via env.
- `TrustScoreController` exposes `/trust-score/calculate` for authenticated callers (primarily diagnostic tooling).

### 4.3 Policy Evaluation
- `PolicyEvaluatorService` wraps Casbin with the `policy/model.conf` and `policy/policy.csv` artifacts; thresholds for deny/challenge decisions are env-driven.
- `PolicyService` offers CRUD plus reload helpers. Admin controller provides REST endpoints guarded by `@Roles('admin')`.
- Evaluation combines subject identity (user + roles) and HTTP method/path; dynamic risk score influences CHALLENGE/DENY outcomes beyond static policy matches.

### 4.4 Proxy & mTLS
- `ServiceRegistryService` maps logical names (`users-service`, etc.) to base URLs from `SERVICE_REGISTRY` JSON or defaults.
- `MtlsService` centralizes certificate loading/caching (CA, cert, key), agent creation, certificate subject allowlists, and validity checks. Config knobs:
  - `MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH`
  - `MTLS_ALLOWED_SUBJECTS` (comma-separated CNs)
- `ProxyService` validates methods/paths, synthesizes identity headers, enforces the service-registry allowlist, rejects unsafe URLs, and forwards via Axios with the prebuilt HTTPS agent. Circuit breaker (failure counts, open/half-open states) and retry logic are parameterized via env. HTTP targets are allowed only when `ALLOW_INSECURE_MICROSERVICE_HTTP=true`.

### 4.5 Audit & Metrics
- `AuditService` ensures every decision (ALLOW/DENY/CHALLENGE/error) is stored with requestId, path, risk, policy reason, and metadata. `AuditRepository` initializes Postgres tables on startup when `DATABASE_URL` is present.
- `MetricsService` registers Prometheus metrics (request counts by decision, trust score histograms, latency buckets). `/metrics` endpoint requires `admin` role.

### 4.6 Gateway Middleware
- Handles every inbound request as a global middleware for all routes except internal admin/diagnostic endpoints.
- Steps: header validation → authentication → trust calculation → policy evaluation → audit logging → metrics → decision enforcement → proxy forwarding.
- Includes request ID propagation, path validation (no traversal or schema injection), and dedicated error handling to ensure consistent responses and audits.

### 4.7 Multi-Factor Authentication (MFA)
- `MfaService` issues one-time challenges whenever policy evaluation returns `CHALLENGE`.
- For development, a 6-digit code is logged to the gateway console to simulate SMS/Email delivery.
- `MfaController` exposes `POST /mfa/verify`, which requires the authenticated user to submit `{ challengeId, code }`. On success it returns a short-lived `mfaToken`.
- Future requests may include the `X-MFA-Token` header; if valid for the user/session, the gateway upgrades the policy decision from CHALLENGE to ALLOW and proceeds to proxy forwarding.

---

## 5. Request Lifecycle
1. **Ingress**: `GatewayMiddleware.use()` logs request ID/method/path; rate limiting and Helmet have already run at the Express layer.
2. **Header/Context Normalization**: Device IDs trimmed and capped; IP derived from Express’ trusted sources rather than arbitrary headers.
3. **Authentication**: `AuthService.validateAuthorizationHeader()` returns `UserClaims` or throws `UnauthorizedException`.
4. **Trust Scoring**: `TrustScoreService.calculateTrustScore()` uses sanitized inputs; errors deny the request and emit 500s (audited).
5. **Policy Evaluation**: `PolicyService.evaluateAccess()` ensures subject is authorized and risk thresholds met; outputs ALLOW/DENY/CHALLENGE.
6. **Audit Log**: Captures decision, factors, and context; resiliency logic prevents failed writes from crashing the request.
7. **Decision Handling**:
   - `DENY` → 403 with reason.
   - `CHALLENGE` → gateway issues an MFA challenge (`challengeId` + expiry) unless the request already carried a valid `X-MFA-Token`.
   - `ALLOW` → path validation then `ProxyService.forwardRequest()`.
8. **Proxy Execution**: Attaches identity headers, enforces the service registry allowlist, obtains HTTPS agent from `MtlsService`, enforces circuit breaker, retries transient failures, and returns downstream response (status+headers+body).
9. **Metrics**: `MetricsService.recordRequestMetrics()` records evaluation latency, forward latency, total latency, decision, trust score.
10. **Error Handling**: Any uncaught error results in audit log entry and standardized 400/500 JSON response via `HttpExceptionFilter`.

---

## 6. Security Posture

### 6.1 Identity
- JWT verification against configured issuer/audience/algorithm.
- Role extraction handles arrays, strings, or Keycloak-style structures.
- Device IDs require server-assigned identifiers or trusted registries; `resolveDeviceId()` prevents header abuse.

### 6.2 Authorization
- Role-based guard for admin endpoints.
- Casbin policies with `keyMatch2` path semantics and regex actions.
- Risk-aware thresholds ensure even authorized users can be challenged/denied when risk spikes.

### 6.3 Network & Transport
- Mutual TLS for all downstream calls; Node TLS hostname verification plus allowed-subject filtering.
- Microservices validate gateway client certificates and optional CN allowlists (`GATEWAY_CLIENT_CERT_CNS`), rejecting non-mTLS traffic unless explicitly allowed.
- SSRF prevention through path validation plus a service registry allowlist.
- Circuit breaker prevents cascading failures.

### 6.4 Input Validation & Hardening
- Global `ValidationPipe` ensures DTOs/queries adhere to schema.
- Rate limiting (`express-rate-limit`) mitigates brute-force attempts.
- Helmet config adds standard security headers.
- All responses carry `x-request-id` for traceability.

### 6.5 Observability
- Audit logs stored in Postgres with request IDs and metadata for forensic analysis.
- Prometheus-ready metrics (decision counters, trust score distribution, latency histograms).
- Optional log aggregation can rely on the request correlation IDs.

---

## 7. Configuration & Deployment

### 7.1 Prerequisites
- Node.js ≥ 16, npm or yarn.
- Postgres if persistent telemetry/audit logging are desired.
- Generated certificates (self-signed dev certs live under `certs/`).

### 7.2 Environment Variables (excerpt)
| Key | Description | Example |
| --- | --- | --- |
| `PORT` | Gateway listening port | `3000` |
| `JWT_SECRET` / `JWT_JWKS_URI` | Shared secret or JWKS endpoint | `a-string-secret...` |
| `JWT_ISSUER`, `JWT_AUDIENCE` | Optional claim enforcement | `https://auth.example.com` |
| `MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH` | Paths to PEM files | `./certs/ca.crt` |
| `MTLS_ALLOWED_SUBJECTS` | Comma-separated CN allowlist | `users-service,orders-service` |
| `GATEWAY_CLIENT_CERT_CNS` | Comma-separated CN allowlist for gateway client certs accepted by microservices | `gateway` |
| `SERVICE_REGISTRY` | JSON map of service → URL | `{"users-service":"https://users:3001"}` |
| `DATABASE_URL` | Postgres connection string | `postgres://user:pass@host/db` |
| `POLICY_DENY_RISK_THRESHOLD` | Score cutoff for DENY | `0.8` |
| `POLICY_CHALLENGE_RISK_THRESHOLD` | Score cutoff for CHALLENGE | `0.5` |
| `MFA_CHALLENGE_TTL_MS` | Lifetime of one-time challenge before it expires | `300000` |
| `MFA_TOKEN_TTL_MS` | Lifetime of post-MFA session token | `600000` |
| `TRUST_*` vars | Weights, frequency windows, retention | See `src/trust-score/trust-score.service.ts` |
| `ALLOW_INSECURE_MICROSERVICE_HTTP` | Allow HTTP-only microservices (dev only) | `false` |
| `STRICT_CONFIG` | Fail fast on missing critical config (or set `NODE_ENV=production`) | `true` |
| `DISABLE_DATABASE` | Disable Postgres-backed persistence (tests) | `true` |

The project ships with `.env` defaults suitable for development; override as needed per environment.

### 7.3 Deployment Modes
- **Local development**: run gateway and sample microservices via `npm run start:dev` and `npx ts-node microservices/...`.
- **Docker Compose (full stack)**: `docker compose up --build` spins up the complete observability stack (see 7.4).
- **Production**: build with `npm run build`, deploy `dist/` artifacts, and supply real certificates and configuration secrets.

### 7.4 Full Observability Stack (Docker Compose)
The top-level `docker-compose.yml` brings up the gateway plus a complete local observability stack with a single command:

```bash
cp .env.example .env   # then fill in the CHANGE_ME secrets
docker compose up --build
```

Services:

| Service | Role | Endpoint |
| --- | --- | --- |
| `gateway` | The zero-trust gateway; exposes `/metrics` | http://localhost:3000 |
| `postgres` | Trust signals, audit WAL, MFA state | localhost:5432 |
| `orders-service` | Sample downstream microservice (mTLS), registered as `orders` in `PROXY_SERVICE_REGISTRY` | internal `:8443` |
| `certgen` | One-shot init that mints the demo PKI (CA + gateway client cert + orders-service server cert) into a shared `certs` volume | — |
| `prometheus` | Scrapes `gateway:3000/metrics` every 15s | http://localhost:9090 |
| `grafana` | Provisioned Prometheus datasource + "ZT Access Gateway — Security Overview" dashboard | http://localhost:3001 |

Grafana logs in as `admin` / `${GRAFANA_ADMIN_PASSWORD:-admin}`. The dashboard panels are built on the real `zt_gateway_*` metric names (request/policy decisions, threat level, JA4H blacklist size, honeypot triggers, hashcash outcomes, pipeline stage latency, audit WAL latency, MFA promotions).

**mTLS note.** The gateway's `ProxyService` always forwards downstream over mutual TLS — there is no plaintext-HTTP path in this build. To keep `docker compose up` runnable end-to-end with no manual steps, the `certgen` init container runs `scripts/gen-certs.sh` once at startup and writes the demo PKI into a named `certs` volume; the gateway and `orders-service` mount it read-only. No certificates are committed to git (`certs/` is gitignored). Configuration files for the observability stack live under `observability/` (`prometheus.yml`, `grafana/provisioning/*`, `grafana/dashboards/*`).

Demonstrate the proxy path once the stack is healthy:

```bash
# Mint a demo JWT (roles=user) and call the gateway, which proxies to orders-service over mTLS.
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register scripts/mint-demo-jwt.ts)"
curl -H "Authorization: Bearer ${TOKEN}" http://localhost:3000/orders/o-1
```

A fresh low-risk request lands ALLOW and returns the deterministic orders body. To force a deterministic trust score, set `DEMO_MODE=true` in `.env` and add `-H "x-demo-trust-score: 0.0"` (the override is honored only when `DEMO_MODE=true`).

The richer demo overlay (`docker-compose.demo.yml`, adds `users-service` for the BOPLA scenario and uses host-mounted certs) is unchanged — see the comments at the top of that file.

### 7.5 Running the UAT scenario suite (`scripts/scenarios/`)

The end-to-end scenario scripts under `scripts/scenarios/` exercise the full pipeline against a running gateway. They require the **demo overlay** — *not* a plain `docker compose up`. The reason: the scripts mint their JWTs using the secret in `.env.demo`, whereas the base `docker-compose.yml` boots the gateway from `.env` (a different `JWT_SECRET`, no `DEMO_MODE`, and no `users-service`). Run them against the base stack and every request is rejected `401` before it reaches the logic under test.

**Prerequisites (host):** `jq`, `node`, and `npm install` having been run (the scripts call `node -r ts-node/register`).

**1. Mint the demo PKI and bring up the demo stack** (gateway boots from `.env.demo`: matching secret, `DEMO_MODE=true` so `x-demo-trust-score` is honoured, and `users-service` registered):

```bash
bash scripts/gen-certs.sh
docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env.demo up --build -d
```

**2. Wait until the gateway is healthy:**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/health   # expect 200
```

**3. Run a scenario** (each is self-contained and exits non-zero on any mismatch):

```bash
bash scripts/scenarios/scenario-1.sh
```

The suite is six scenarios, one per major pipeline flow:

| Scenario | What it verifies | Pipeline stages exercised |
| --- | --- | --- |
| `scenario-1` | Happy path — low-risk `GET /orders/o-1` lands ALLOW → `200` + deterministic body. | auth, trust score, policy ALLOW, mTLS proxy |
| `scenario-2` | Rejected credentials — no token → `401`, bad-signature → `401`, and revoke-then-replay → `401 token_revoked`. | auth, revocation |
| `scenario-3` | Honeypot deception + enforcement — `GET /.env` → deceptive `200`, same fingerprint again → `403` (tarpit), and `x-ja4h` propagated downstream. | JA4H fingerprint, honeypot, terminal blacklist |
| `scenario-4` | High-risk → hashcash PoW → MFA step-up — `429` PoW → solve → `401 mfa_required` → enroll/confirm/initiate/verify (real TOTP) → promote → `200`. | trust score (high), hashcash, policy CHALLENGE, MFA promotion |
| `scenario-5` | Policy DENY — `DELETE /orders/o-1` as a `user` → `403 policy_denied` (Casbin no-match), while the same user's `GET` → `200`. | policy DENY (RBAC) |
| `scenario-6` | BOPLA — `GET /users/u-1` returns only role-permitted fields (`ssn`, `internalRiskScore` stripped). Needs `users-service` (demo overlay). | mTLS proxy, BOPLA field-level authz |

This runs cleanly in order (`for n in 1 2 3 4 5 6; do bash scripts/scenarios/scenario-$n.sh; done`).

**Re-running and per-process state.** Several defences keep **per-process in-memory state** (the JA4H blacklist, the hashcash used-nonce store, the JTI revocation list). `scenario-3` is self-contained — it trips *and* re-hits the trap within one run — but its terminal blacklist entry for the `curl` fingerprint persists in the gateway process, so a **second** run of `scenario-3` would see a `403` on the first hit instead of the fresh deceptive `200`. The other five use authenticated requests (distinct fingerprints) and are safely repeatable. To re-run the whole suite from a clean slate, restart the gateway (clears in-memory state, keeps the database):

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env.demo restart gateway
```

**Troubleshooting.** If `/health` returns `000` (connection refused) and the gateway container is `Restarting`, check `docker logs <gateway-container>`. A `password authentication failed for user "ztgateway" (28P01)` means a **stale `pgdata` volume** is holding an old `POSTGRES_PASSWORD` (Postgres only applies the password when it first initialises an empty data dir). Reset it with a volume-dropping teardown, then bring the stack back up:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env.demo down -v
docker compose -f docker-compose.yml -f docker-compose.demo.yml --env-file .env.demo up --build -d
```

---

## 8. Operational Playbooks

### 8.1 Policy Administration
1. Authenticate with an admin JWT.
2. Use `/policy/admin/rules` (GET/POST/DELETE) to view or mutate bindings.
3. Invoke `/policy/admin/reload` after editing on-disk CSV (or move to DB-backed store).
4. Every mutation is audited; cross-reference `audit_logs` for change history.

### 8.2 Certificate Rotation
1. Upload new CA/cert/key files to the configured paths.
2. Call `MtlsService.clearCache()` via a maintenance script or restart the gateway.
3. Verify `createAgent()` succeeds and Prometheus metrics indicate healthy downstream calls.

### 8.3 Metrics & Monitoring
1. Admins fetch `/metrics` for scraping by Prometheus.
2. Alerts can be built on `zt_gateway_requests_total` (high DENY/CHALLENGE ratios) or latency histograms.
3. Combine metrics with audit logs for incident investigations.

### 8.4 Trust Telemetry Maintenance
1. Ensure `DATABASE_URL` is set so telemetry persists.
2. Schedule cleanup jobs (already triggered in `calculateTrustScore()`) to keep activity tables trimmed.
3. Consider integrating external IP reputation feeds via additional DB columns.

### 8.5 MFA Challenge Workflow
MFA uses **TOTP** (RFC 6238) — a 6-digit code from an authenticator app — not an out-of-band code. The user must enrol once before they can answer challenges.

**Enrollment (one-time):**
1. `POST /mfa/enroll` with the JWT authorization header. The response returns an `enrollmentId` and an `otpauthUri`; the client renders the URI as a QR code for the user's authenticator app. The TOTP secret never leaves the server.
2. `POST /mfa/enroll/confirm` with body `{ "enrollmentId": "...", "totpCode": "XXXXXX" }` to prove the authenticator is set up. (Admins can reset a user's enrollment via `DELETE /mfa/admin/enrollment/:userId`.)

**Answering a challenge:**
1. When the pipeline returns `401` with reason `mfa_required` (and a `WWW-Authenticate` / `X-MFA-Challenge` header), call `POST /mfa/initiate` with the JWT authorization header to open a challenge. The response is `{ challengeId, expiresAt }`.
2. Submit `POST /mfa/verify` with the JWT authorization header and body `{ "challengeId": "...", "totpCode": "XXXXXX" }`.
3. On success the response is `{ token, expiresAt }`. Store `token` and include it as the `X-MFA-Token` header on subsequent requests until it expires. The MFA token is bound to `SHA-256(userId | deviceId | ip)`, so it cannot be replayed from another device or network.
4. Repeat the flow whenever the trust engine raises another CHALLENGE or the token expires.

The `scenario-8` script (§7.5) drives this exact flow end-to-end with a real TOTP code, including the per-user rate limit (`429`).

---

## 9. Development Workflow

### 9.1 Installation
```bash
npm install
```

### 9.2 Building
```bash
npm run build
```

### 9.3 Local Services
```
Terminal 1: npm run start:dev              # Gateway on :3000
Terminal 2: ./create-certs.sh              # Generate dev certs
Terminal 3: npx ts-node microservices/users-service/main.ts
Terminal 4: npx ts-node microservices/orders-service/main.ts
Terminal 5: npx ts-node microservices/permissions-service/main.ts
```
Microservices require mTLS by default; set `ALLOW_INSECURE_MICROSERVICE_HTTP=true` only for local HTTP fallback.

### 9.4 Testing
```bash
npm test
npm run test:cov
```
Tests are colocated with their modules under `__tests__` folders, covering auth, proxy, trust, policy, audit, and gateway error handling.

### 9.5 Sample Request
1. Generate a JWT with `JWT_SECRET` (e.g., `a-string-secret-at-least-256-bits-long`) and payload `{ "userId": "test-user", "roles": ["user"], "sessionId": "session123", "iss": "local-issuer", "aud": "zt-access-gateway" }`.
2. Call the gateway:
```bash
curl -H "Authorization: Bearer <TOKEN>" http://localhost:3000/users
```

---

## 10. Future Enhancements
- Persist Casbin policies in Postgres and add revision history.
- Integrate device attestation and hardware-backed IDs into trust scoring.
- Add OpenTelemetry tracing and correlate spans with audit records.
- Provide automated policy compliance suites (e.g., OPA conformance or fuzz testing).

---

This whitepaper should equip new contributors and reviewers with a holistic understanding of the Zero-Trust Access Gateway, from conceptual motivations down to operational procedures. For deeper dives, consult source files referenced above or the inline tests that demonstrate expected behavior.
