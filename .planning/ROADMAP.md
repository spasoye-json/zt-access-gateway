# Roadmap: Zero-Trust Access Gateway

## Overview

Rebuild from a bare NestJS scaffold to a fully hardened zero-trust access gateway using TDD and real libraries from day one. Construction follows the strict pipeline dependency chain: foundation first, then each pipeline stage in execution order, and finally the GatewayMiddleware integrator that wires everything together. Each phase is independently testable before the next begins.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Typed config, shared utilities, and bootstrap stack (Helmet, CORS, rate limiting) (completed 2026-04-13)
- [x] **Phase 2: JA4H + Honeypot** - HTTP fingerprinting, fingerprint blacklist, and shadow honeypot decoy routes (completed 2026-04-13)
- [x] **Phase 3: Auth + Token Revocation** - JWT validation (HS256/RS256/ES256 + JWKS), UserClaims, and JTI blacklist (completed 2026-04-18)
- [x] **Phase 4: Trust Score** - 7-signal risk scoring model with Postgres persistence and DB test isolation (completed 2026-04-22)
- [x] **Phase 5: Hashcash PoW** - Proof-of-work guard for high-risk requests with difficulty scaling (completed 2026-04-26)
- [x] **Phase 6: Policy + Threat Escalation** - Casbin RBAC evaluation, ALLOW/CHALLENGE/DENY, and auto-tightening thresholds (completed 2026-04-26)
- [x] **Phase 7: MFA Challenge** - Fingerprint-bound TOTP challenge lifecycle and CHALLENGE-to-ALLOW promotion (completed 2026-05-03)
- [ ] **Phase 8: Proxy + BOPLA** - mTLS forwarding with circuit breaker/retries/SSRF and role-based response field stripping
- [ ] **Phase 9: Audit + Metrics** - Write-ahead audit buffer and Prometheus security metrics
- [ ] **Phase 10: Gateway Integration** - 10-step fail-fast GatewayMiddleware orchestrating the full hardened pipeline

## Phase Details

### Phase 1: Foundation
**Goal**: The application starts, validates its own configuration, and provides the shared infrastructure all pipeline modules depend on
**Depends on**: Nothing (first phase)
**Requirements**: CONF-01, CONF-02, CONF-03, SHRD-01, SHRD-02, SHRD-03, SHRD-04, SHRD-05, SHRD-06, SHRD-07, BOOT-01, BOOT-02, BOOT-03, BOOT-04, BOOT-05
**Success Criteria** (what must be TRUE):
  1. Application refuses to start and prints a clear error when any required env var is missing
  2. MtlsService loads, caches, and invalidates certs on mtime change without restarting the process
  3. Requests to undefined routes receive structured JSON errors with no stack traces or internal detail
  4. GET /health returns a service status response without passing through any auth or security checks
  5. Bootstrap applies Helmet headers, CORS, and rate limiting before any request reaches business logic
**Plans:** 3/3 plans complete
Plans:
- [x] 01-01-PLAN.md — ConfigModule with Joi validation and typed AppConfigService
- [x] 01-02-PLAN.md — SharedModule: MtlsService, CertMonitorService, RequestContext, exception filter, health endpoint
- [x] 01-03-PLAN.md — Bootstrap main.ts middleware stack, Docker Compose, Dockerfile, e2e smoke tests

### Phase 2: JA4H + Honeypot
**Goal**: Every request carries a JA4H fingerprint computed from raw headers, blacklisted fingerprints are tarpitted and rejected, and decoy routes silently identify and flag scanners
**Depends on**: Phase 1
**Requirements**: JA4H-01, JA4H-02, JA4H-03, JA4H-05, JA4H-06, HPOT-01, HPOT-02, HPOT-03, HPOT-04, HPOT-05, HPOT-06, HPOT-07
**Success Criteria** (what must be TRUE):
  1. Every request has an x-ja4h header value computed from method + HTTP version + ordered header names + accept + content-type
  2. A request with a blacklisted JA4H fingerprint receives a 403 after a 2-5 second tarpit delay
  3. A request to /wp-login.php, /.env, or any other decoy route receives a realistic fake JSON response after a delay
  4. A honeypot hit causes the requester's JA4H fingerprint to be added to the blacklist and their trust score set to 1.0
  5. Each honeypot trigger increments the zt_gateway_honeypot_triggers_total Prometheus counter and produces an audit log entry
**Plans:** 2/2 plans complete
Plans:
- [x] 02-01-PLAN.md — FingerprintModule: config extension, FingerprintStore blacklist, Ja4hMiddleware, computeJa4h utility
- [x] 02-02-PLAN.md — HoneypotModule: SecurityMetricsService, ShadowController with 7 decoy routes, AppModule wiring

### Phase 3: Auth + Token Revocation
**Goal**: Only requests bearing a valid, non-revoked JWT with correct algorithm and claims can proceed past the authentication gate
**Depends on**: Phase 1
**Requirements**: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07, AUTH-08, TREV-01, TREV-02, TREV-03, TREV-04, JA4H-04
**Success Criteria** (what must be TRUE):
  1. A request with a valid HS256/RS256/ES256 JWT proceeds past the auth guard with UserClaims attached
  2. A request with a "none" algorithm token, expired token, or tampered signature receives a 401
  3. A request with a token whose jti has been revoked via POST /auth/revoke receives a 401
  4. Revocation blacklist entries expire automatically when the original token would have expired
  5. Routes decorated with @Public() bypass JWT validation entirely
**Plans:** 3/3 plans complete
Plans:
- [x] 03-01-PLAN.md — TDD Wave 0: test stubs, shared key fixtures, e2e jest config
- [x] 03-02-PLAN.md — AuthService (jose jwtVerify), JwtAuthGuard, RolesGuard, @Roles(), JWT config group
- [x] 03-03-PLAN.md — TokenRevocationService, AuthController POST /auth/revoke, e2e pipeline test

### Phase 4: Trust Score
**Goal**: Each authenticated request receives a computed 0.0-1.0 risk score from 7 signals, with trust context persisted to Postgres only on ALLOW decisions
**Depends on**: Phase 3
**Requirements**: TRST-01, TRST-02, TRST-03, TRST-04, TRST-05, TRST-06, TRST-07, TRST-08, TRST-09, TRST-10
**Success Criteria** (what must be TRUE):
  1. A request from a JA4H-blacklisted fingerprint immediately receives score 1.0 without evaluating other signals
  2. A mid-session JA4H change (fingerprint drift) adds +0.3 to the computed risk score
  3. Trust signals and activity records are written to Postgres after a successful ALLOW, never after CHALLENGE or DENY
  4. TrustDecayEngine reduces favorable trust factors over idle time using exponential decay
  5. DB unit tests use transaction-per-test rollback so each test starts with clean state
**Plans:** 3/3 plans complete
Plans:
- [x] 04-01-PLAN.md — deviceId + TRUST config + SQL migration + Jest DB setup + repository reads
- [x] 04-02-PLAN.md — signal providers + TrustScoreService.evaluateScore
- [x] 04-03-PLAN.md — record-after-ALLOW + TrustScoreModule + AppModule + TRST-09 tests

### Phase 5: Hashcash PoW
**Goal**: Requests with risk score above 0.7 are blocked until the client solves a proof-of-work challenge scaled to their risk level
**Depends on**: Phase 4
**Requirements**: HCSH-01, HCSH-02, HCSH-03, HCSH-04, HCSH-05, HCSH-06, HCSH-07
**Success Criteria** (what must be TRUE):
  1. A request with risk score > 0.7 receives a 429 with X-Hashcash-Challenge header containing nonce:difficulty
  2. Difficulty is 18 bits at score 0.7 and scales up to 22 bits at score 0.9
  3. A request carrying a valid X-Hashcash-Solution (SHA-256(nonce+solution) has required leading zero bits) proceeds through the pipeline
  4. PoW challenges issued, solved, and failed are tracked as Prometheus metrics
**Plans:** 9 plans
Plans:
- [x] 05-00-PLAN.md — Wave 0 test stubs (six __tests__/ spec files with describe/it.todo skeletons)
- [x] 05-01-PLAN.md — hashcash.util.ts pure functions (difficultyForScore, countLeadingZeroBits, hashSolution)
- [x] 05-02-PLAN.md — UsedNonceStore in-memory bounded LRU (single-use replay defense, D-04)
- [x] 05-03-PLAN.md — HashcashService HMAC issue/verify with timing-safe compare and D-11 difficulty re-derive
- [x] 05-04-PLAN.md — HashcashMetrics: prom-client Counter + Histogram on a private Registry
- [x] 05-05-PLAN.md — HashcashGuard + HashcashModule, wire into AppModule after AuthModule (Pitfall 2)
- [x] 05-06-PLAN.md — Full e2e cycle test: 429 → solve at 4 bits → 200 → replay rejected
- [x] 05-07-PLAN.md — HASHCASH_* config group (Joi + AppConfigService getters)
- [x] 05-08-PLAN.md — Gap closure: D-02 identity binding (verifySolution + guard threading)

### Phase 6: Policy + Threat Escalation
**Goal**: Every request receives an ALLOW, CHALLENGE, or DENY decision from Casbin RBAC combined with risk score thresholds, with thresholds auto-tightening under threat conditions
**Depends on**: Phase 4
**Requirements**: PLCY-01, PLCY-02, PLCY-03, PLCY-04, PLCY-05, PLCY-06, PLCY-07, PLCY-08, PLCY-09, PLCY-10, PLCY-11
**Success Criteria** (what must be TRUE):
  1. A request with score below challenge threshold and a matching Casbin rule receives ALLOW
  2. A request with score above deny threshold or no matching Casbin rule receives DENY
  3. A Casbin enforcer error always results in DENY, never in accidental ALLOW
  4. After detecting repeated DENYs or failed MFA, ThreatEscalationService automatically tightens thresholds and restores them via auto-cooldown
  5. Runtime policy rules can be added and removed via the policy admin REST API without restarting the process
**Plans**: 7 plans
Plans:
- [x] 06-00-PLAN.md — Wave 0: install deps (casbin, event-emitter, async-mutex), patch model.conf [role_definition], add 14 POLICY_*/THREAT_* config vars + Joi cross-field validator
- [x] 06-01-PLAN.md — Pure types + utils (PolicyDecision, policy-events, policy-subject.util, PolicyMetrics)
- [x] 06-02-PLAN.md — PolicyEvaluatorService (Casbin enforcer, fail-closed evaluate, writer-mutex mutators)
- [x] 06-03-PLAN.md — ThreatEscalationService (sliding-window aggregator, level transitions, cooldown, manual override)
- [x] 06-04-PLAN.md — PolicyAdminController + DTOs (rules CRUD + escalation override)
- [x] 06-05-PLAN.md — Cross-phase emitter patches (auth.invalid_token in JwtAuthGuard, honeypot.trigger in ShadowController)
- [x] 06-06-PLAN.md — PolicyModule + AppModule wiring + full HTTP e2e

### Phase 7: MFA Challenge
**Goal**: A CHALLENGE decision can be resolved by the client submitting a valid TOTP code, producing a fingerprint-bound MFA token that promotes the request to ALLOW
**Depends on**: Phase 6
**Requirements**: MFA-01, MFA-02, MFA-03, MFA-04, MFA-05, MFA-06, MFA-07, MFA-08
**Success Criteria** (what must be TRUE):
  1. POST /mfa/verify with a valid TOTP code creates an MFA JWT signed with MFA_JWT_SECRET (separate from main JWT_SECRET)
  2. An MFA token replayed from a different IP or device fingerprint is rejected with 401
  3. MFA challenge initiation is rejected after exceeding the per-user rate limit within the configured time window
  4. MFA tokens expire and are stored in mfa_tokens table; expired tokens are rejected
**Plans:** 4 plans
Plans:
- [x] 07-00-PLAN.md — Wave 0: install otplib + v12-adapter, MFA Joi config (6 env vars + cross-field TTL validator), 005_mfa_tables.sql migration, all test stubs
- [x] 07-01-PLAN.md — Data layer: aes-gcm.util.ts, MfaTokenClaims interface, 3 raw-pg repositories, MFA_RATE_LIMITED event, express.d.ts augmentation
- [x] 07-02-PLAN.md — MfaService: createChallenge, verifyTotp, validateMfaToken (discriminated unions, never-throw)
- [x] 07-03-PLAN.md — MfaController + MfaGuard + MfaModule + AppModule wiring + REQUIREMENTS.md MFA-04 amendment

### Phase 8: Proxy + BOPLA
**Goal**: Allowed requests are forwarded to downstream services via mTLS with header sanitization, circuit breaking, and retry; responses have unauthorized fields stripped based on caller's roles
**Depends on**: Phase 1
**Requirements**: PRXY-01, PRXY-02, PRXY-03, PRXY-04, PRXY-05, PRXY-06, PRXY-07, PRXY-08, PRXY-09, BOPL-01, BOPL-02, BOPL-03, BOPL-04
**Success Criteria** (what must be TRUE):
  1. Forwarded requests reach downstream services over mTLS with Authorization/Cookie headers stripped and x-user-id/x-roles/x-trust-score/x-gateway-request injected
  2. A request targeting a service not in PROXY_SERVICE_REGISTRY is rejected with an appropriate error before any network call is made
  3. DnsRebindingGuard prevents forwarding to private/loopback/metadata IP ranges resolved at connection time
  4. After a configured failure threshold the circuit breaker opens; failing fast until half-open probe succeeds
  5. Admin-role callers receive all response fields; lower-privilege roles receive progressively restricted field sets per the field policy
**Plans:** 5 plans
Plans:
- [x] 08-00-PLAN.md — Wave 0: install opossum + @types, Joi/getter group, express.d.ts, field-policy.json starter, RED test stubs
- [x] 08-01-PLAN.md — ServiceRegistryService + DnsRebindingGuard + ResponseValidator (independent helpers)
- [ ] 08-02-PLAN.md — ProxyService: opossum per-service breakers + retry loop + header sanitization + mTLS forwarding
- [ ] 08-03-PLAN.md — BoPlaInterceptor: field-policy.json load + recursive role-based field stripping (BOPL-01..04)
- [ ] 08-04-PLAN.md — ProxyModule + AppModule wiring + module bootstrap integration test

### Phase 9: Audit + Metrics
**Goal**: Every gateway decision is durably recorded to an audit log before the request is allowed through, and all pipeline activity is observable via Prometheus
**Depends on**: Phase 1
**Requirements**: AUDT-01, AUDT-02, AUDT-03, AUDT-04, AUDT-05, AUDT-06, MTRC-01, MTRC-02, MTRC-03, MTRC-04, MTRC-05
**Success Criteria** (what must be TRUE):
  1. Every ALLOW/CHALLENGE/DENY decision produces an audit_logs row with userId, resource, action, decision, trust score, JA4H fingerprint, and timestamp
  2. An ALLOW request is denied if the write-ahead audit buffer exhausts all retries (max 3) without successfully persisting the audit record
  3. GET /metrics returns Prometheus-format counters for allow/challenge/deny decisions, latency histograms per pipeline stage, and security-specific metrics (honeypot triggers, hashcash challenges, escalation level changes, token revocations)
  4. An audit persistence failure never throws an unhandled exception; it increments audit_failure_total and logs a warning
**Plans:** TBD (not yet planned)

### Phase 10: Gateway Integration
**Goal**: All 10 pipeline steps execute in the correct fail-fast order for every request, with public routes bypassed, trust context written only on ALLOW, and MFA promotion working end-to-end
**Depends on**: Phase 9
**Requirements**: GTWY-01, GTWY-02, GTWY-03, GTWY-04, GTWY-05, GTWY-06, GTWY-07, GTWY-08, GTWY-09
**Success Criteria** (what must be TRUE):
  1. A request passes through all 10 steps (JA4H -> blacklist -> rate limit -> honeypot -> auth -> revocation -> trust score -> hashcash -> policy -> proxy) in that exact order
  2. A blacklisted JA4H fingerprint never reaches the auth stage; an unauthenticated request never reaches the trust scorer
  3. A CHALLENGE decision triggers the MFA flow; a valid MFA token presented on the next request promotes it to ALLOW without re-evaluating policy
  4. Trust signals are written to Postgres after a successful proxy response on ALLOW; a CHALLENGE or DENY produces zero new trust_signals rows
  5. GET /health and GET /metrics are reachable without a JWT and without triggering any pipeline stage
**Plans:** TBD (not yet planned)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 3/3 | Complete | 2026-04-13 |
| 2. JA4H + Honeypot | 2/2 | Complete | 2026-04-13 |
| 3. Auth + Token Revocation | 3/3 | Complete | 2026-04-18 |
| 4. Trust Score | 3/3 | Complete | 2026-04-22 |
| 5. Hashcash PoW | 9/9 | Complete | 2026-04-26 |
| 6. Policy + Threat Escalation | 7/7 | Complete | 2026-04-26 |
| 7. MFA Challenge | 4/4 | Complete | 2026-05-03 |
| 8. Proxy + BOPLA | 0/5 | Planned | - |
| 9. Audit + Metrics | 0/TBD | Not started | - |
| 10. Gateway Integration | 0/TBD | Not started | - |
| 11. MFA Enrollment | 5/5 | Complete | 2026-05-03 |

### Phase 11: MFA Enrollment

**Goal**: Authenticated users can self-service enroll a TOTP authenticator app via a two-step flow (generate secret → confirm TOTP), with admin-gated re-enrollment via DELETE /mfa/admin/enrollment/:userId
**Depends on**: Phase 7
**Requirements**: ENROLL-01, ENROLL-02, ENROLL-03, ENROLL-04, ENROLL-05, ENROLL-06, ENROLL-07, ENROLL-08, ENROLL-09, ENROLL-10, CONF-11
**Success Criteria** (what must be TRUE):
  1. POST /mfa/enroll returns a D-03-compliant otpauth URI without persisting any secret to the database
  2. POST /mfa/enroll/confirm validates the user-submitted TOTP code; only on success the AES-256-GCM-encrypted secret is written to user_secrets
  3. A user with an existing user_secrets row receives 409 Conflict on POST /mfa/enroll until an admin resets them
  4. DELETE /mfa/admin/enrollment/:userId requires the admin role and emits mfa.enrollment_reset for audit observability
  5. Pending enrollment state is in-memory-only with lazy TTL eviction; the plaintext secret is never logged or persisted before confirm
**Plans:** 5 plans
Plans:
- [x] 11-00-PLAN.md — Wave 0 RED: failing specs for PendingEnrollmentStore + MfaService enrollment + e2e
- [x] 11-01-PLAN.md — Config getters (MFA_ISSUER_NAME, MFA_ENROLL_PENDING_TTL_MS) + PendingEnrollmentStore + MFA_ENROLLMENT_RESET event
- [x] 11-02-PLAN.md — UserSecretsRepository write methods (save upsert, deleteByUserId) + EnrollConfirmDto
- [x] 11-03-PLAN.md — MfaService createEnrollment / confirmEnrollment / deleteEnrollment + MfaModule wiring
- [x] 11-04-PLAN.md — MfaController routes + REQUIREMENTS.md amendment + ROADMAP finalization
