# Requirements: Zero-Trust Access Gateway

**Defined:** 2026-04-11 · **Traceability refresh:** 2026-04-18
**Core Value:** Every request is verified, scored, and authorized before reaching any downstream service

## v1 Requirements

Requirements for initial release. Full hardened architecture including fail-fast pipeline, JA4H fingerprinting, honeypots, hashcash PoW, BOPLA interceptor, threat escalation, and audit WAL.

### Configuration

- [x] **CONF-01**: Application fails fast at startup if required env vars are missing
- [x] **CONF-02**: Typed config service exposes validated env values for all modules
- [x] **CONF-03**: Typed config (Joi) validates and exposes env for shipped modules to date — foundation (port, CORS, rate limit, mTLS paths), fingerprint/honeypot, JWT. Database, proxy, MFA, policy, hashcash, and full metrics groups are added as their phases land (see `src/config/config.module.ts`).

### Shared Infrastructure

- [x] **SHRD-01**: MtlsService loads CA cert, client cert, and client key from filesystem paths
- [x] **SHRD-02**: MtlsService caches certs and invalidates on file mtime change
- [x] **SHRD-03**: MtlsService validates server certificate CN against MTLS_ALLOWED_SUBJECTS allowlist
- [x] **SHRD-04**: CertMonitorService watches cert files and triggers reload on changes
- [x] **SHRD-05**: RequestContext utility extracts IP, user-agent, and device fingerprint from request
- [x] **SHRD-06**: Global exception filter returns structured JSON errors without leaking internals
- [x] **SHRD-07**: Health endpoint returns service status without passing through the security pipeline

### JA4H Fingerprinting

- [x] **JA4H-01**: JA4H middleware computes fingerprint from req.rawHeaders (header names in original order + casing)
- [x] **JA4H-02**: JA4H hash is SHA-256 of method + HTTP version + ordered header names + accept + content-type
- [x] **JA4H-03**: Computed JA4H fingerprint is attached to request context as x-ja4h
- [x] **JA4H-04**: `UserClaims` includes `userId` and optional `sessionId` (and `deviceId`) so downstream phases can correlate JA4H drift and trust signals; `FingerprintStore` remains keyed by JA4H hash globally. Per-user fingerprint *indexing* in the store is deferred to Gateway integration (Phase 10) per Phase 3 CONTEXT.
- [x] **JA4H-05**: FingerprintStore maintains a blacklist of JA4H fingerprints with configurable TTL
- [x] **JA4H-06**: Blacklisted JA4H fingerprints are rejected immediately with 403 (after tarpit delay)

### Shadow Honeypot

- [x] **HPOT-01**: ShadowController registers decoy routes (/wp-login.php, /admin/config.json, /.env, /api/v1/debug, /graphql/introspection, /actuator/health, /api/v1/internal/keys)
- [x] **HPOT-02**: @Honeypot() decorator marks controller methods as decoy handlers
- [x] **HPOT-03**: Any hit to a decoy route blacklists the JA4H fingerprint in FingerprintStore
- [x] **HPOT-04**: Honeypot triggers set trust score to 1.0 (terminal) for the session/IP
- [x] **HPOT-05**: Decoy routes return realistic fake JSON responses (tarpitting with 2-5s delay)
- [x] **HPOT-06**: Every honeypot trigger is audit-logged with HONEYPOT_TRIGGERED event and full request metadata
- [x] **HPOT-07**: Prometheus counter zt_gateway_honeypot_triggers_total is incremented on each trigger

### Authentication

- [x] **AUTH-01**: AuthService validates JWT signatures for HS256, RS256, and ES256 algorithms
- [x] **AUTH-02**: AuthService rejects tokens with wrong algorithm, expired claims, or tampered signatures
- [x] **AUTH-03**: AuthService rejects tokens using "none" algorithm
- [x] **AUTH-04**: AuthService fetches and caches JWKS keys when JWKS_URI is configured
- [x] **AUTH-05**: AuthService validates issuer and audience claims when `JWT_ISSUER` / `JWT_AUDIENCE` are set (optional when unset)
- [x] **AUTH-06**: JwtAuthGuard extracts UserClaims (userId, roles, email, sessionId, deviceId) from validated token
- [x] **AUTH-07**: JwtAuthGuard skips validation for routes decorated with @Public()
- [x] **AUTH-08**: RolesGuard enforces @Roles() decorator requirements

### Token Revocation

- [x] **TREV-01**: TokenRevocationService maintains in-memory blacklist keyed by JWT jti claim
- [x] **TREV-02**: Blacklist entries auto-expire when the original token would have expired (no unbounded memory growth)
- [x] **TREV-03**: POST /auth/revoke accepts body with `jti` and `exp`, enforces ownership (user revokes own JTI; `admin` role may revoke any)
- [x] **TREV-04**: JwtAuthGuard checks revocation after `jwtVerify`, before attaching `request.user` (trust scoring not yet in pipeline — order matches target Gateway step)

### Trust Score (7-Signal Model)

- [x] **TRST-01**: TrustScoreService computes a 0.0-1.0 score from 7 signals: device reputation, IP reputation, JA4H fingerprint drift, request frequency, trust decay, behavior anomaly, honeypot blacklist
- [x] **TRST-02**: Honeypot blacklist is a terminal signal — if JA4H is blacklisted, score is immediately 1.0 (skip all other signals)
- [x] **TRST-03**: JA4H fingerprint drift detection: mid-session JA4H change adds +0.3 to risk score (high-confidence session hijack signal)
- [x] **TRST-04**: TrustDecayEngine applies exponential decay e^(-idleMs / halfLifeMs) to favorable trust factors
- [x] **TRST-05**: BehaviorAnomalyService computes 0.0-0.4 additive risk from deviation against user's behavioral profile
- [x] **TRST-06**: Base score is 0.5 with device (+-0.15), IP (+-0.15), JA4H (-0.05/+0.30), frequency (-0.10/+0.20) adjustments, clamped to 0.0-1.0
- [x] **TRST-07**: Trust signals are persisted to trust_signals table in Postgres
- [x] **TRST-08**: Trust activity history is recorded in trust_activity table
- [x] **TRST-09**: Trust context is only recorded on ALLOW decisions (after successful proxy), never on CHALLENGE or DENY
- [x] **TRST-10**: TrustTelemetryRepository reads/writes trust data with proper connection pooling

### Hashcash Proof of Work

- [x] **HCSH-01
**: HashcashGuard activates when risk score > 0.7 (high risk)
- [x] **HCSH-02
**: Challenge is issued via 429 response with X-Hashcash-Challenge header containing nonce:difficulty
- [x] **HCSH-03
**: Difficulty scales with risk score (0.7 -> 18 bits, 0.9 -> 22 bits)
- [x] **HCSH-04
**: Client submits solution via X-Hashcash-Solution header
- [x] **HCSH-05
**: Verification checks SHA-256(nonce + solution) has required leading zero bits
- [x] **HCSH-06
**: Valid PoW allows request to continue through the pipeline
- [x] **HCSH-07
**: Metrics track PoW challenges issued, solved, and failed

### Policy

- [x] **PLCY-01**: PolicyEvaluatorService loads Casbin model and policy from filesystem (model.conf + policy.csv)
- [x] **PLCY-02**: Policy evaluates user:<id> and role:<role> subjects against requested resource and action
- [x] **PLCY-03**: Policy returns ALLOW when score < challenge threshold and Casbin permits
- [x] **PLCY-04**: Policy returns CHALLENGE when score >= challenge threshold but < deny threshold
- [x] **PLCY-05**: Policy returns DENY when score >= deny threshold or Casbin denies
- [x] **PLCY-06**: PolicyService exposes REST API for runtime policy management (add/remove rules)
- [x] **PLCY-07**: Challenge and deny thresholds are configurable via env vars
- [x] **PLCY-08**: ThreatEscalationService monitors audit signals (repeated DENYs, failed MFA, invalid tokens, high anomaly scores)
- [x] **PLCY-09**: Threat escalation auto-tightens thresholds at Elevated (DENY>0.6, CHALLENGE>0.3) and Critical (DENY>0.4, CHALLENGE>0.2) levels
- [x] **PLCY-10**: Threat escalation includes auto-cooldown decay back to normal thresholds
- [x] **PLCY-11**: Admin endpoint POST /policy/admin/escalation allows manual override/reset of threat level

### MFA

- [ ] **MFA-01**: MfaService creates challenge records in mfa_challenges table tied to authenticated user
- [ ] **MFA-02**: MfaService validates TOTP codes against stored challenge
- [ ] **MFA-03**: Valid MFA verification produces a signed MFA JWT (using MFA_JWT_SECRET, separate from main JWT_SECRET)
- [ ] **MFA-04**: MFA token is bound to device + IP fingerprint (SHA-256 of userId|deviceId|ip) — geolocation and user-agent excluded per D-07 (Phase 4 D-14 alignment)
- [ ] **MFA-05**: MFA token redemption rejects tokens whose fingerprint doesn't match current request context
- [ ] **MFA-06**: MfaController exposes endpoint for challenge submission and token verification
- [ ] **MFA-07**: MFA tokens are stored in mfa_tokens table with expiry
- [ ] **MFA-08**: MFA challenge initiation is rate-limited per user per time window

### MFA Enrollment (Phase 11)

- [ ] **ENROLL-01**: POST /mfa/enroll generates a TOTP secret and returns 201 with { enrollmentId, otpauthUri } for an authenticated, unenrolled user (D-01)
- [ ] **ENROLL-02**: otpauthUri is D-03 compliant — contains scheme `otpauth://totp/`, label `<issuer>:<email-or-userId>` (URL-encoded), and explicit `secret`, `issuer`, `algorithm=SHA1`, `digits=6`, `period=30` query params
- [ ] **ENROLL-03**: POST /mfa/enroll returns 409 Conflict with `{ error: 'already_enrolled' }` when the user already has a user_secrets row (D-06)
- [ ] **ENROLL-04**: POST /mfa/enroll/confirm with a valid 6-digit TOTP writes the AES-256-GCM-encrypted secret to user_secrets and returns 200 (D-04)
- [ ] **ENROLL-05**: POST /mfa/enroll/confirm with an invalid TOTP returns 400 with reason `invalid_totp` and does NOT delete the pending enrollment entry (D-04 retry semantic)
- [ ] **ENROLL-06**: PendingEnrollmentStore evicts pending entries lazily after MFA_ENROLL_PENDING_TTL_MS (default 600000 ms) on next read (D-02)
- [ ] **ENROLL-07**: DELETE /mfa/admin/enrollment/:userId requires the `admin` role and returns 200 with `{ deleted: <bool> }` indicating whether a row was removed (D-07)
- [ ] **ENROLL-08**: DELETE /mfa/admin/enrollment/:userId emits `mfa.enrollment_reset` event so admin resets are audit-observable
- [ ] **ENROLL-09**: All enrollment endpoints return 401 when no Authorization header is present (JwtAuthGuard at class level)
- [ ] **ENROLL-10**: DELETE /mfa/admin/enrollment/:userId returns 403 for callers without the `admin` role (method-level @Roles)
- [ ] **CONF-11**: AppConfigService exposes typed `mfaIssuerName` (default `ZT-Gateway`) and `mfaEnrollPendingTtlMs` (default 600000) getters validated by Joi (D-11)

### Proxy

- [ ] **PRXY-01**: ProxyService forwards allowed requests to downstream services via mTLS
- [ ] **PRXY-02**: ProxyService strips Authorization/Cookie headers and injects x-user-id, x-roles, x-trust-score, x-gateway-request headers
- [ ] **PRXY-03**: ServiceRegistryService validates target against PROXY_SERVICE_REGISTRY allowlist (SSRF protection)
- [ ] **PRXY-04**: ProxyService implements circuit breaker (CLOSED -> OPEN -> HALF-OPEN state machine)
- [ ] **PRXY-05**: ProxyService retries failed requests with exponential backoff
- [ ] **PRXY-06**: Proxy rejects requests targeting services not in the registry
- [ ] **PRXY-07**: DnsRebindingGuard resolves hostnames to IPs before connecting and validates resolved IP is not in private/loopback/metadata ranges
- [ ] **PRXY-08**: DNS resolution cross-checks resolved IP against service registry allowlist
- [ ] **PRXY-09**: ResponseValidator validates downstream response before returning to client

### BOPLA Response Interceptor

- [ ] **BOPL-01**: BOPLA interceptor strips unauthorized fields from downstream JSON responses based on user roles
- [ ] **BOPL-02**: @AuthorizedFields decorator or field-policy.json defines which roles can see which fields per route
- [ ] **BOPL-03**: Field stripping handles nested objects and arrays of objects recursively
- [ ] **BOPL-04**: Admin role sees all fields; lower roles see progressively restricted field sets

### Audit

- [ ] **AUDT-01**: AuditService logs every gateway decision (ALLOW/CHALLENGE/DENY) to audit_logs table
- [ ] **AUDT-02**: Audit log includes userId, resource, action, decision, trust score, timestamp, request metadata, and JA4H fingerprint
- [ ] **AUDT-03**: WriteAheadBuffer guarantees audit entries are persisted before allowing requests through (audit-before-allow for ALLOW decisions)
- [ ] **AUDT-04**: WAL retries with exponential backoff (max 3 retries); if exhausted, DENY the request
- [ ] **AUDT-05**: AuditController exposes read-only endpoint for audit log queries
- [ ] **AUDT-06**: Honeypot triggers are logged with HONEYPOT_TRIGGERED event type

### Metrics

- [ ] **MTRC-01**: MetricsService exposes Prometheus counters for requests by decision type (allow/challenge/deny)
- [ ] **MTRC-02**: MetricsService exposes histograms for request latency per pipeline stage
- [ ] **MTRC-03**: MetricsController serves metrics at GET /metrics in Prometheus exposition format
- [ ] **MTRC-04**: SecurityMetrics tracks honeypot triggers, hashcash challenges/solutions, threat escalation level changes, token revocations
- [ ] **MTRC-05**: SecurityMetrics tracks JA4H blacklist size and fingerprint drift detections

### Gateway Integration (10-Step Fail-Fast Pipeline)

- [ ] **GTWY-01**: GatewayMiddleware orchestrates the 10-step fail-fast pipeline: JA4H -> Blacklist check -> Rate limit -> Honeypot -> Auth -> Token revocation -> Trust score -> Hashcash PoW -> Policy -> Proxy
- [ ] **GTWY-02**: Pipeline ordered so cheapest rejections happen first (JA4H blacklist before auth, auth before trust scoring)
- [ ] **GTWY-03**: GatewayMiddleware short-circuits on DENY at any stage (returns appropriate status code)
- [ ] **GTWY-04**: GatewayMiddleware triggers MFA flow on CHALLENGE and promotes to ALLOW on valid MFA token
- [ ] **GTWY-05**: GatewayMiddleware records trust context only after successful proxy on ALLOW
- [ ] **GTWY-06**: BOPLA interceptor runs on response path after proxy, before returning to client
- [ ] **GTWY-07**: Audit + metrics recording happens after proxy response
- [ ] **GTWY-08**: Public routes (health, metrics) bypass the full pipeline
- [ ] **GTWY-09**: Tarpit delay applied to blacklisted JA4H fingerprints (2-5s before 403)

### Bootstrap

- [x] **BOOT-01**: Application applies JA4H middleware as first middleware in chain
- [x] **BOOT-02**: Application applies rate limiting (IP-based global throttler) before auth pipeline
- [x] **BOOT-03**: Application applies Helmet security headers
- [x] **BOOT-04**: Application configures CORS from env-based allowed origins
- [x] **BOOT-05**: Docker Compose provides gateway + Postgres for local development (full microservices / Prometheus / Grafana stack deferred — see `docker-compose.yml` comments)

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Enhanced Trust Scoring

- **TRST-20**: Trust score signal weights configurable via env vars
- **TRST-21**: IP reputation enhanced with ASN and VPN/proxy detection
- **TRST-22**: JWKS caching with configurable TTL and force-refresh endpoint

### Scaling

- **SCAL-01**: Redis-backed distributed trust state for horizontal scaling
- **SCAL-02**: Distributed rate limiting across multiple gateway instances

### Eventing

- **EVNT-01**: Webhook / event emission on policy decisions for SIEM integration
- **EVNT-02**: Per-service policy overrides (service-level Casbin policies)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Frontend admin UI | Doubles attack surface; policy-as-code in CSV is git-auditable |
| OAuth2/SAML IdP integration | Gateway validates JWTs from any issuer; IdP integration is a separate product |
| Stateful sessions | Breaks horizontal scalability; requires Redis; JWTs are stateless by design |
| WebSocket proxying | Orthogonal to per-request ZT policy; complex lifecycle management |
| ML-based anomaly detection | 5% of value for 20x complexity; heuristic scoring covers the risk surface |
| Built-in IdP (user/password management) | Completely different domain; delegate to external IdP |
| DLP / payload inspection | Latency + legal risk (PII in logs); out of scope for metadata-layer gateway |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONF-01 | Phase 1 | Complete |
| CONF-02 | Phase 1 | Complete |
| CONF-03 | Phase 1 | Complete |
| SHRD-01 | Phase 1 | Complete |
| SHRD-02 | Phase 1 | Complete |
| SHRD-03 | Phase 1 | Complete |
| SHRD-04 | Phase 1 | Complete |
| SHRD-05 | Phase 1 | Complete |
| SHRD-06 | Phase 1 | Complete |
| SHRD-07 | Phase 1 | Complete |
| BOOT-01 | Phase 1 | Complete |
| BOOT-02 | Phase 1 | Complete |
| BOOT-03 | Phase 1 | Complete |
| BOOT-04 | Phase 1 | Complete |
| BOOT-05 | Phase 1 | Complete |
| JA4H-01 | Phase 2 | Complete |
| JA4H-02 | Phase 2 | Complete |
| JA4H-03 | Phase 2 | Complete |
| JA4H-04 | Phase 3 | Complete |
| JA4H-05 | Phase 2 | Complete |
| JA4H-06 | Phase 2 | Complete |
| HPOT-01 | Phase 2 | Complete |
| HPOT-02 | Phase 2 | Complete |
| HPOT-03 | Phase 2 | Complete |
| HPOT-04 | Phase 2 | Complete |
| HPOT-05 | Phase 2 | Complete |
| HPOT-06 | Phase 2 | Complete |
| HPOT-07 | Phase 2 | Complete |
| AUTH-01 | Phase 3 | Complete |
| AUTH-02 | Phase 3 | Complete |
| AUTH-03 | Phase 3 | Complete |
| AUTH-04 | Phase 3 | Complete |
| AUTH-05 | Phase 3 | Complete |
| AUTH-06 | Phase 3 | Complete |
| AUTH-07 | Phase 3 | Complete |
| AUTH-08 | Phase 3 | Complete |
| TREV-01 | Phase 3 | Complete |
| TREV-02 | Phase 3 | Complete |
| TREV-03 | Phase 3 | Complete |
| TREV-04 | Phase 3 | Complete |
| TRST-01 | Phase 4 | Complete |
| TRST-02 | Phase 4 | Complete |
| TRST-03 | Phase 4 | Complete |
| TRST-04 | Phase 4 | Complete |
| TRST-05 | Phase 4 | Complete |
| TRST-06 | Phase 4 | Complete |
| TRST-07 | Phase 4 | Complete |
| TRST-08 | Phase 4 | Complete |
| TRST-09 | Phase 4 | Complete |
| TRST-10 | Phase 4 | Complete |
| HCSH-01 | Phase 5 | Complete |
| HCSH-02 | Phase 5 | Complete |
| HCSH-03 | Phase 5 | Complete |
| HCSH-04 | Phase 5 | Complete |
| HCSH-05 | Phase 5 | Complete |
| HCSH-06 | Phase 5 | Complete |
| HCSH-07 | Phase 5 | Complete |
| PLCY-01 | Phase 6 | Complete |
| PLCY-02 | Phase 6 | Complete |
| PLCY-03 | Phase 6 | Complete |
| PLCY-04 | Phase 6 | Complete |
| PLCY-05 | Phase 6 | Complete |
| PLCY-06 | Phase 6 | Complete |
| PLCY-07 | Phase 6 | Complete |
| PLCY-08 | Phase 6 | Complete |
| PLCY-09 | Phase 6 | Complete |
| PLCY-10 | Phase 6 | Complete |
| PLCY-11 | Phase 6 | Complete |
| MFA-01 | Phase 7 | Pending |
| MFA-02 | Phase 7 | Pending |
| MFA-03 | Phase 7 | Pending |
| MFA-04 | Phase 7 | Pending |
| MFA-05 | Phase 7 | Pending |
| MFA-06 | Phase 7 | Pending |
| MFA-07 | Phase 7 | Pending |
| MFA-08 | Phase 7 | Pending |
| ENROLL-01 | Phase 11 | Pending |
| ENROLL-02 | Phase 11 | Pending |
| ENROLL-03 | Phase 11 | Pending |
| ENROLL-04 | Phase 11 | Pending |
| ENROLL-05 | Phase 11 | Pending |
| ENROLL-06 | Phase 11 | Pending |
| ENROLL-07 | Phase 11 | Pending |
| ENROLL-08 | Phase 11 | Pending |
| ENROLL-09 | Phase 11 | Pending |
| ENROLL-10 | Phase 11 | Pending |
| CONF-11   | Phase 11 | Pending |
| PRXY-01 | Phase 8 | Pending |
| PRXY-02 | Phase 8 | Pending |
| PRXY-03 | Phase 8 | Pending |
| PRXY-04 | Phase 8 | Pending |
| PRXY-05 | Phase 8 | Pending |
| PRXY-06 | Phase 8 | Pending |
| PRXY-07 | Phase 8 | Pending |
| PRXY-08 | Phase 8 | Pending |
| PRXY-09 | Phase 8 | Pending |
| BOPL-01 | Phase 8 | Pending |
| BOPL-02 | Phase 8 | Pending |
| BOPL-03 | Phase 8 | Pending |
| BOPL-04 | Phase 8 | Pending |
| AUDT-01 | Phase 9 | Pending |
| AUDT-02 | Phase 9 | Pending |
| AUDT-03 | Phase 9 | Pending |
| AUDT-04 | Phase 9 | Pending |
| AUDT-05 | Phase 9 | Pending |
| AUDT-06 | Phase 9 | Pending |
| MTRC-01 | Phase 9 | Pending |
| MTRC-02 | Phase 9 | Pending |
| MTRC-03 | Phase 9 | Pending |
| MTRC-04 | Phase 9 | Pending |
| MTRC-05 | Phase 9 | Pending |
| GTWY-01 | Phase 10 | Pending |
| GTWY-02 | Phase 10 | Pending |
| GTWY-03 | Phase 10 | Pending |
| GTWY-04 | Phase 10 | Pending |
| GTWY-05 | Phase 10 | Pending |
| GTWY-06 | Phase 10 | Pending |
| GTWY-07 | Phase 10 | Pending |
| GTWY-08 | Phase 10 | Pending |
| GTWY-09 | Phase 10 | Pending |

**Coverage:**
- v1 requirements: 120 total (3 CONF + 1 CONF11 + 7 SHRD + 6 JA4H + 7 HPOT + 8 AUTH + 4 TREV + 10 TRST + 7 HCSH + 11 PLCY + 8 MFA + 10 ENROLL + 9 PRXY + 4 BOPL + 6 AUDT + 5 MTRC + 9 GTWY + 5 BOOT)
- Mapped to phases: 120
- Unmapped: 0

---
*Requirements defined: 2026-04-11*
*Last updated: 2026-05-03 — Phase 11 (MFA Enrollment) ENROLL-01..ENROLL-10 + CONF-11 added*
