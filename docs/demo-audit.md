# Demo-Path Audit

(Read-only audit. Microservices and DEMO_MODE wiring not yet built — this file scores everything
*else* assuming those land.)

## Scenario-by-scenario verdict

| # | Scenario | Verdict | One-line reason |
|---|---|---|---|
| 1 | Happy path (score 0.2 → ALLOW → proxy) | YELLOW | Pipeline correct end-to-end, but mTLS is mandatory in MtlsService — gateway will refuse to start without real certs and CN matching `MTLS_ALLOWED_SUBJECTS`. |
| 2 | Auth failure (no Authorization) → 401 | YELLOW | 401 fires correctly, BUT **no audit row** is written for auth-stage denials — thesis evidence gap. |
| 3 | Honeypot probe → DENY | YELLOW | Scenario named `/admin/.env` — actual honeypot constant is `/.env` (works) or `/wp-login.php`. Also **no `audit_logs` row** — only a console.warn from ShadowController. Plus 2-5s tarpit makes the demo feel slow. |
| 4 | Score 0.7 → HASHCASH → MFA → 200 | RED | (a) `HASHCASH_TRIGGER_THRESHOLD` default is **0.7**, and the gate is `score > threshold`, so score 0.7 **does not trigger hashcash** — must use 0.71+ or drop the env to 0.6. (b) MFA token cannot be obtained without a 4-step setup (enroll → enroll/confirm → initiate → verify); no quick-issue helper exists. (c) Hashcash short-circuit returns **429** (`proof_of_work_required`) not 401 as the brief assumed. |
| 5 | Revoked-JTI replay → 401 | YELLOW | RevocationStage works as designed, BUT `TokenRevocationService.revoke(jti, expiresAt, userId)` requires 3 args — a `x-demo-revoke-jti` helper has to construct expiresAt+userId itself, and there is **no audit row** for the deny. |
| 6 | BOPLA strip on `/users/u-1` | GREEN | BoplaInterceptor + `policy/field-policy.json` are fully wired. `role:user` on `/users/**` is whitelisted to `[id, email, name]` — `ssn`/`internalRiskScore` get stripped automatically. |

Net: **1 RED, 4 YELLOW, 1 GREEN.**

## Critical gaps (must fix before demo)

- **[hashcash threshold off-by-one]** `src/gateway/pipeline/stages/hashcash.stage.ts:44` — `if (trustScoreValue <= threshold) return continue;` paired with `HASHCASH_TRIGGER_THRESHOLD=0.7` makes score **exactly 0.7** skip the gate. Either set `HASHCASH_TRIGGER_THRESHOLD=0.6` in the demo `.env`, or use `x-demo-trust-score: 0.75` in scenario 4. Document the chosen value in the demo runbook.
- **[MFA bootstrap is 4 endpoints]** Reaching scenario 4b requires: `POST /mfa/enroll` (gets `otpauthUri` and TOTP secret), `POST /mfa/enroll/confirm` (with TOTP code from authenticator app — `src/shared/totp.util.ts`), `POST /mfa/initiate` (creates challengeId), `POST /mfa/verify` (returns the MFA JWT). All four require a valid base JWT. There is **no shortcut** today. Either (a) script the 4 calls into a demo helper that pre-runs once and stashes the MFA JWT, or (b) add a `DEMO_MODE` admin route that mints an MFA JWT directly via `MfaChallenger`'s private `signJwt` path (or expose a one-shot `mintDemoMfaToken` method).
- **[mTLS mandatory]** `src/shared/mtls.service.ts` + `src/config/slices/mtls.config.ts` — `MTLS_CA_CERT_PATH`, `MTLS_CLIENT_CERT_PATH`, `MTLS_CLIENT_KEY_PATH`, `MTLS_ALLOWED_SUBJECTS` are all required and there is **no `MTLS_DISABLED` toggle**. `ProxyService.forward` unconditionally calls `mtls.getHttpsAgent()` and uses that agent for the axios call. The whole `MtlsService.loadCertificates()` runs at first proxy. For a demo against http(s) microservices you must either (a) generate a 3-cert PKI (CA + client + server-with-CN-in-allowlist) into the microservices, or (b) add a `MTLS_DISABLED=true` short-circuit in MtlsService/ProxyService that returns undefined and lets axios use plain http. Option (b) is ~10 LOC.
- **[auth/honeypot/revocation outcomes leave no audit row]** `audit_logs` is only written from AuditAllowStage (allow), MfaPromotionStage (challenge/deny), and AuthOnlyShortCircuitStage. AuthStage (scenario 2), RevocationStage (scenario 5), HoneypotBypassStage + ShadowController (scenario 3) all bail out before any `AuditService.log()` call. Thesis defense will want a clean grid: "every scenario produced one row in `audit_logs`". Fix sketch: add `audit.log({decision: 'deny', resource, action, ...})` calls before the `short-circuit` return in `auth.stage.ts:43-72`, `revocation.stage.ts:33-38`, and inside `ShadowController.trapAndRespond()` (use `userId: 'anonymous'`).

## Yellow flags (worth checking during rehearsal)

- **[score injection seam]** `src/gateway/pipeline/stages/trust-score.stage.ts:25-39` is the cleanest place to honor `x-demo-trust-score` — `ctx.req.headers` is available, you set `ctx.trustScore` and `req.trustScore` right there. `TrustContext` itself (`src/trust-score/trust-context.ts`) has no headers field, so do NOT plumb the override into `TrustScoreService.evaluateScore`; intercept above it. ~5 LOC inside `TrustScoreStage.run`.
- **[honeypot path mismatch]** Brief lists `/admin/.env`; actual constants in `src/honeypot/honeypot.constants.ts` are `/.env`, `/wp-login.php`, `/admin/config.json`, `/api/v1/debug`, `/graphql/introspection`, `/actuator/health`, `/api/v1/internal/keys`. Adjust the demo curl to one of those.
- **[honeypot tarpit 2-5s]** `ShadowController.trapAndRespond` sleeps `randomDelay(2000,5000)` before responding. Live demo will look broken; consider adding a `DEMO_MODE` skip or shorter delay (`50ms`) for the rehearsal.
- **[hashcash short-circuit returns 429, not 401]** Update the demo script's expected status.
- **[Casbin `/users/:id` matches via keyMatch2]** `policy/policy.csv` allows `role:user GET /users/:id` so `/users/u-1` will pass policy with score 0.2. Just don't lower-case the path; `normalizeResource` preserves case.
- **[`role:user` subject construction]** `src/policy/policy-subject.util.ts:14` — Casbin subjects are `user:<id>` and `role:<role>`. JWT must include `roles: ['user']` (or `['admin']`). The demo JWT generator must set that claim or `casbinAllow=false → DENY`.
- **[`PROXY_SERVICE_REGISTRY` shape]** `src/proxy/service-registry.service.ts:67` — service name is the **first path segment**. `/users/u-1` → service `users` must be in `PROXY_SERVICE_REGISTRY`. After strip the upstream sees `/u-1`. Build microservices accordingly.
- **[`jti` required on every JWT]** `src/auth/auth.service.ts:37` — `requiredClaims: ['jti','sub']`. Demo JWT generator must always include `jti`. Otherwise auth fails before revocation can even fire.
- **[ALLOW audit is fail-closed]** `src/gateway/pipeline/stages/audit-allow.stage.ts:42` may throw `AuditExhaustedException` → 503 with `Retry-After:5`. If Postgres is flaky during the live demo, scenario 1 fails with 503 even though everything else worked. Verify the docker-compose `postgres` healthcheck is solid; consider raising `AUDIT_WAL_MAX_RETRIES` for the demo.
- **[`x-demo-revoke-jti` setup]** `TokenRevocationService.revoke(jti, expiresAtMs, userId)` is purely in-memory — fine for demo, but it does NOT persist across gateway restarts. Whichever helper writes the demo revocation should also be re-runnable so a restart between rehearsals doesn't lose state.
- **[`AuthController.revoke` already exists]** `POST /auth/revoke` works and is in `AUTH_ONLY_EXACT` — you could simply call this endpoint with the user's own token (non-admin self-revoke) and skip the `x-demo-revoke-jti` middleware idea entirely.

## Nice-to-haves (skip for now)

- ThreatEscalationService (`src/policy/threat-escalation.service.ts`) reacts to event bus signals — fine to leave at defaults; won't change scenario behavior in a single-request demo.
- `BoPlaInterceptor.strip()` recurses with the same allow-list on nested objects — sufficient for the flat `{id,name,email,ssn,internalRiskScore}` body, but worth eyeballing if the demo body changes shape.
- Circuit breaker (`opossum` in ProxyService) — defaults are sane; no action needed for a happy-path demo.
- Casbin `policy/policy.csv` does not include `role:user PUT` or `DELETE`. Stick to GET methods in the demo.
- DNS rebinding guard (`src/proxy/dns-rebinding.guard.ts`) — make sure the docker-compose service names resolve to private IPs only (which they do by default in compose networks).

## Cross-cutting notes

- **Stage wiring is complete.** All 13 stages declared in `src/gateway/pipeline/stages/` are wired into `PIPELINE_STAGES` in `src/gateway/gateway.module.ts:75-105` in execution order. There is no `FingerprintStage` in the pipeline list — that's correct: JA4H runs as a NestJS middleware (`Ja4hMiddleware`) BEFORE `GatewayMiddleware` is invoked (see `src/app.module.ts:80-81`). No stub or `throw new Error("not implemented")` branches found in any stage. No critical TODOs in pipeline code.
- **MFA promotion path is real.** Not a stub: `MfaPromotionStage.run` at `src/gateway/pipeline/stages/mfa-promotion.stage.ts:35-100` validates the `x-mfa-token` header via `MfaChallenger.validateMfaToken` (`src/mfa/mfa-challenger.service.ts`), full jose `jwtVerify`, fingerprint binding `SHA-256(userId|deviceId|ip)`, `typ:'mfa'` claim, optional JTI revocation. Promotion to `continue` is real. Only friction is the 4-step bootstrap (see RED above).
- **BOPLA is real.** `BoPlaInterceptor.strip` (`src/proxy/bopla.interceptor.ts:48-103`) is allow-list based with admin-passthrough, fail-closed default, micromatch glob patterns, recursive descent on nested objects/arrays. Policy file at `policy/field-policy.json` already maps `/users/**` for `role:user` to `[id, email, name]`. Demo scenario 6 will Just Work once the upstream returns the test body.
- **mTLS is the single biggest mechanical hurdle** for getting upstream traffic flowing. Plan one of: (i) generate a local PKI (5 mins with `openssl`) and bake certs into both gateway and each microservice container, with CNs added to `MTLS_ALLOWED_SUBJECTS`; or (ii) add a one-line `MTLS_DISABLED` toggle.
- **DB seeding & migrations.** `src/main.ts:12-30` runs all `sql/migrations/*.sql` on boot from a fresh `pg.Client`. Files 004/005/006 exist (trust_score, mfa_tables, audit_logs). 001–003 are absent — confirm before demo that fingerprint store / trust signal / honeypot tables are either created elsewhere or not required (FingerprintStore is in-memory; trust_signals tables are inside `004_trust_score.sql`). Quick verify: `\dt` after `docker-compose up` and you should see `trust_signals`, `trust_activity`, `mfa_challenges`, `mfa_tokens`, `user_secrets`, `audit_logs`.
- **Audit row coverage is the main thesis-evidence gap.** Scenarios 1, 4 (challenge + allow rows), 6 produce DB rows. Scenarios 2, 3, 5 do not. Fix sketch above under Critical Gaps — 3 small `audit.log` calls and you get a clean evidence table for the defense.
- **`HASHCASH_TRIGGER_THRESHOLD` default 0.7 vs scenario score 0.7** is the single most likely cause of "I ran the demo and the wrong thing happened" on the day. Lower it to 0.6 in the demo `.env` and call it out in the runbook.
- **Honeypot tarpit will hurt the demo cadence.** 2-5 seconds per probe will feel like a hang. A `DEMO_MODE` branch that short-circuits the `randomDelay` (or sets a 50ms ceiling) keeps the deception story intact without dragging.
- **AUTH_ONLY paths.** `/auth/revoke`, `/mfa/initiate`, `/mfa/verify`, `/mfa/enroll`, `/mfa/enroll/confirm` and `/audit/logs` all run auth+revocation only then `next()` to their controllers. That means scenario 5 can use the live `POST /auth/revoke` endpoint as the setup helper — no new middleware needed.
