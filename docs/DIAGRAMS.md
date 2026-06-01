# Zero-Trust Access Gateway — Flowcharts & Sequence Diagrams

This document contains Mermaid flowcharts and sequence diagrams describing the **current** architecture of the gateway: a pre-pipeline JA4H fingerprinting middleware followed by a **13-stage fail-fast orchestrated pipeline**. Every diagram reflects the code as it exists today (method names, stage order, and exit conditions are taken straight from source).

Render in any Markdown viewer that supports Mermaid (e.g. GitHub, GitLab, VS Code with a Mermaid extension).

For the *why* behind these mechanics see [`HARDENING_ARCHITECTURE.md`](./HARDENING_ARCHITECTURE.md); for a prose, step-by-step walkthrough of a request see [`THESIS_PIPELINE.md`](./THESIS_PIPELINE.md).

---

## Table of contents

1. [System overview](#1-system-overview)
2. [The 13-stage data-plane pipeline](#2-the-13-stage-data-plane-pipeline)
3. [Data-plane happy-path sequence (ALLOW)](#3-data-plane-happy-path-sequence-allow)
4. [Authentication: JWT validation](#4-authentication-jwt-validation)
5. [Trust score: seven signals](#5-trust-score-seven-signals)
6. [Policy evaluation](#6-policy-evaluation)
7. [MFA: enroll, challenge & verify](#7-mfa-enroll-challenge--verify)
8. [Proxy forward](#8-proxy-forward)
9. [Bootstrap & module wiring](#9-bootstrap--module-wiring)

---

## 1. System overview

A request first hits the global Express middleware configured in `main.ts` (Helmet → CORS → rate-limit), then the DI-aware `Ja4hMiddleware`, and finally the `GatewayMiddleware`, which delegates the request to the `PipelineOrchestrator`. The orchestrator runs the 13 stages in canonical order and returns on the first non-`continue` outcome. Public paths, honeypot decoys, and control-plane (auth-only) paths short-circuit early; only fully-authorized data-plane requests reach the mTLS proxy and the downstream microservices.

```mermaid
flowchart TB
  Client[Client]

  subgraph Edge["Edge hardening (main.ts global middleware)"]
    direction TB
    Helmet[helmet]
    Cors[CORS]
    RateLimit[express-rate-limit -> 429]
  end

  subgraph Ja4h["Ja4hMiddleware (DI-aware, pre-pipeline)"]
    Compute[computeJa4h: SHA-256 of method/httpVersion/header-names/accept/content-type]
    Blacklist{Blacklisted JA4H?}
    Tarpit[tarpit 2-5s -> 403 Forbidden]
  end

  subgraph Gateway["GatewayMiddleware -> PipelineOrchestrator"]
    Pipeline[13 stages, first-non-continue wins]
  end

  subgraph ControlPlane["Control-plane controllers (auth_only bypass)"]
    MfaCtl[MfaController /mfa/*]
    AuditCtl[AuditController /audit/logs]
    PolicyCtl[PolicyAdminController /policy/admin]
    AuthCtl[AuthController /auth/revoke]
    Metrics[MetricsController /metrics]
    Health[Health /health]
    Shadow[ShadowController honeypot decoys]
  end

  subgraph Downstream["Downstream microservices (mTLS)"]
    Users[users-service]
    Orders[orders-service]
    Perms[permissions-service]
  end

  subgraph Persistence["Persistence & observability"]
    Postgres[(Postgres: trust, mfa, audit, user_secrets)]
    Prom[Prometheus /metrics]
  end

  Client --> Helmet --> Cors --> RateLimit --> Compute
  Compute --> Blacklist
  Blacklist -->|Yes| Tarpit
  Blacklist -->|No| Pipeline

  Pipeline -->|public_bypass| Health
  Pipeline -->|public_bypass| Metrics
  Pipeline -->|honeypot_bypass| Shadow
  Pipeline -->|auth_only| MfaCtl
  Pipeline -->|auth_only| AuditCtl
  Pipeline -->|auth_only| PolicyCtl
  Pipeline -->|auth_only| AuthCtl

  Pipeline -->|proxy| Users
  Pipeline -->|proxy| Orders
  Pipeline -->|proxy| Perms

  Pipeline -.audit/trust.-> Postgres
  MfaCtl -.-> Postgres
  AuditCtl -.-> Postgres
  Metrics -.-> Prom
```

---

## 2. The 13-stage data-plane pipeline

`PipelineOrchestrator.run()` iterates the `PIPELINE_STAGES` list (assembled in canonical order by the factory provider in `gateway.module.ts`) and returns the first stage outcome whose `kind` is not `continue`. A `bypass` invokes Express `next()` so a controller handles the request; a `short-circuit` writes a terminal HTTP response; `proxied` writes the upstream response. The fail-closed ALLOW audit (stage 10) is written **before** the proxy call (stage 11) — if the WAL is exhausted the request is rejected with 503 and never reaches downstream.

```mermaid
flowchart TD
  Start([Orchestrator.run]) --> S1

  S1[1. public_bypass]
  S1 -->|/health, /metrics| BypassA[bypass -> next -> controller]
  S1 -->|else| S2

  S2[2. honeypot_bypass]
  S2 -->|7 decoy paths| BypassB[bypass -> ShadowController: blacklist JA4H + tarpit + fake 200]
  S2 -->|else| S3

  S3[3. auth: AuthService.authenticate]
  S3 -->|invalid| D401a[short-circuit 401 auth_required / auth_invalid + deny audit]
  S3 -->|ok -> ctx.claims| S4

  S4[4. revocation: TokenRevocationService.isRevoked jti]
  S4 -->|revoked| D401b[short-circuit 401 token_revoked + deny audit]
  S4 -->|not revoked| S5

  S5[5. auth_only short-circuit]
  S5 -->|/auth/revoke, /mfa/*, /audit/logs, /policy/admin*, /demo/mfa-token| BypassC[best-effort allow audit -> bypass -> controller]
  S5 -->|else| S6

  S6[6. trust_score: TrustScoreService.evaluateScore]
  S6 --> S7

  S7[7. hashcash PoW gate]
  S7 -->|trustScore > triggerThreshold AND missing/invalid solution| D429[short-circuit 429 + X-Hashcash-Challenge]
  S7 -->|score <= threshold OR valid solution| S8

  S8[8. policy: PolicyEvaluatorService.evaluate -> ctx.policyDecision]
  S8 --> S9

  S9[9. mfa_promotion]
  S9 -->|DENY| D403[short-circuit 403 policy_denied + deny audit]
  S9 -->|CHALLENGE + no/invalid X-MFA-Token| D401c[short-circuit 401 mfa_required + challenge / 429 / 503]
  S9 -->|ALLOW, or CHALLENGE promoted by valid X-MFA-Token| S10

  S10[10. audit_allow: FAIL-CLOSED WAL written BEFORE proxy]
  S10 -->|AuditExhaustedException| D503[short-circuit 503 audit_unavailable + Retry-After: 5]
  S10 -->|written| S11

  S11[11. proxy: ProxyService.forward via mTLS]
  S11 -->|ServiceUnavailable / circuit open| D502[502 proxy_unavailable]
  S11 -->|upstream response| S12

  S12[12. bopla_strip: BoPlaInterceptor.strip field allowlist]
  S12 --> S13

  S13[13. record_trust_context]
  S13 -->|upstreamStatus < 400| Rec[recordTrustContextAfterAllow]
  S13 -->|>= 400| NoRec[skip - no reputation farming]
  Rec --> Done[proxied -> write upstream response + allow metric]
  NoRec --> Done
```

---

## 3. Data-plane happy-path sequence (ALLOW)

End-to-end sequence for a single proxied request that is authenticated, low-risk, and policy-ALLOWed. The fail-closed ALLOW audit precedes the proxy call; trust context is recorded only after a successful (`< 400`) upstream response.

```mermaid
sequenceDiagram
  autonumber
  participant Client
  participant Ja4h as Ja4hMiddleware
  participant Orch as PipelineOrchestrator
  participant Auth as AuthService
  participant Rev as TokenRevocationService
  participant Trust as TrustScoreService
  participant Policy as PolicyEvaluatorService
  participant Mfa as MfaChallenger
  participant Audit as AuditService
  participant Proxy as ProxyService
  participant Bopla as BoPlaInterceptor
  participant Svc as Microservice

  Client->>Ja4h: HTTP request (Authorization, path)
  Ja4h->>Ja4h: computeJa4h -> attach x-ja4h (not blacklisted)
  Ja4h->>Orch: next() -> GatewayMiddleware -> run(ctx)
  Orch->>Auth: authenticate(req)
  Auth-->>Orch: { kind: 'ok', claims } (ctx.claims set)
  Orch->>Rev: isRevoked(claims.jti)
  Rev-->>Orch: false
  Note over Orch: not an auth_only path -> continue
  Orch->>Trust: evaluateScore(trustCtx)
  Trust-->>Orch: score (ctx.trustScore)
  Note over Orch: hashcash: score <= triggerThreshold -> continue
  Orch->>Policy: evaluate(req)
  Policy-->>Orch: { decision: 'ALLOW', score, reason }
  Note over Orch,Mfa: ALLOW -> MFA promotion is a no-op
  Orch->>Audit: log(allow entry)  [fail-closed WAL, BEFORE proxy]
  Audit-->>Orch: persisted
  Orch->>Proxy: forward(req, claims, trustScore)
  Proxy->>Svc: HTTPS + mTLS (x-user-id, x-roles, x-trust-score, x-ja4h)
  Svc-->>Proxy: response
  Proxy-->>Orch: { status, data } (ctx.upstreamStatus/Body)
  Orch->>Bopla: strip(upstreamBody, reqPath, roles)
  Bopla-->>Orch: strippedBody
  Orch->>Trust: recordTrustContextAfterAllow(trustCtx, score)  [only if status < 400]
  Orch-->>Client: proxied -> upstream status + stripped body
```

---

## 4. Authentication: JWT validation

`AuthService.authenticate()` extracts the `Bearer` token, then `validateToken()` decodes the protected header and **routes by algorithm**: `HS256` verifies against the symmetric secret; `RS256`/`ES256` verify against a local SPKI public key or a cached remote JWKS. The accepted algorithm set is pinned to `[HS256, RS256, ES256]` (so `alg: none` and any substitution are rejected), `jti` + `sub` are required claims, and a token carrying `typ: 'mfa'` is rejected here (MFA tokens are only valid via `MfaChallenger.validateMfaToken`). Failures become `UnauthorizedException` values, surfaced as a 401 by `AuthStage`.

```mermaid
sequenceDiagram
  participant Stage as AuthStage
  participant Auth as AuthService
  participant jose
  participant Config as AuthConfig

  Stage->>Auth: authenticate(req)
  Auth->>Auth: split "Bearer <token>"
  alt missing / wrong scheme
    Auth-->>Stage: { kind: 'invalid', reason: 'missing' | 'scheme' }
  end
  Auth->>Auth: validateToken(token)
  Auth->>jose: decodeProtectedHeader(token) -> header.alg
  Note over Auth: options pin algorithms [HS256, RS256, ES256]; require jti + sub
  alt alg == HS256
    Auth->>Config: jwtSecret
    Auth->>jose: jwtVerify(token, secret, options)
  else alg == RS256 or ES256
    alt jwtPublicKey present
      Auth->>jose: importSPKI -> jwtVerify(token, key, options)
    else jwksUri present
      Auth->>jose: createRemoteJWKSet (cached) -> jwtVerify(token, jwks, options)
    end
  else any other alg (incl. none)
    Auth-->>Stage: UnauthorizedException "Algorithm not allowed"
  end
  jose-->>Auth: payload
  alt payload.typ == 'mfa'
    Auth-->>Stage: UnauthorizedException "MFA token cannot be used as access token"
  end
  Auth->>Auth: extractClaims (sub, roles[], jti, exp, deviceId required)
  Auth-->>Stage: { kind: 'ok', claims: UserClaims }
```

---

## 5. Trust score: seven signals

`TrustScoreService.evaluateScore()` returns a non-terminal score in `[0,1]`. If the request's JA4H is **terminal-blacklisted**, it returns `1.0` immediately with no DB reads. Otherwise it evaluates the three signal-rules plus the JA4H-drift and behavior-anomaly providers in parallel, then applies the Trust-Decay post-processor, sums all deltas onto a `0.5` baseline, and clamps to `[0,1]`. Any provider fault contributes a `+0.1` risk bias rather than crashing. There is **no geolocation signal**.

```mermaid
flowchart TD
  Start([evaluateScore ctx: userId, deviceId, ip, ja4h]) --> Term{ja4h terminal-blacklisted?}
  Term -->|Yes| One[return 1.0 - no DB reads]
  Term -->|No| Phase1

  subgraph Phase1["Phase 1 - parallel (fault -> +0.1 bias)"]
    direction TB
    DevRep[device_reputation: countAllowsForUserDeviceIp >= known -> -0.15 else +0.15]
    IpRep[ip_reputation: sumAllowsForUserIp >= known -> -0.15 else +0.15]
    Freq[request_frequency: count in window > max -> +0.2 else -0.1]
    Drift[ja4h_drift: stored != current -> +0.3 ; stable -> -0.05]
    Anom[behavior_anomaly: hour-histogram + rate z-scores, clamp 0..0.4]
  end

  Phase1 --> Decay[Phase 2 - trust_decay: k = exp -idleMs/halfLife attenuates favourable decayable deltas]
  Decay --> Sum[deltaSum = sum of all adjustments]
  Sum --> Clamp[clamp 0..1 of 0.5 + deltaSum]
  Clamp --> Out([trust score])
```

---

## 6. Policy evaluation

`PolicyEvaluatorService.evaluate()` builds Casbin subjects (`user:<id>` plus `role:<role>` for each role) and tests them against the resource + action. The Casbin path is fully wrapped: **any enforcer error returns DENY (`policy_error`)** — it never defaults to allow. When a subject matches, the trust score is mapped using the **live** challenge/deny thresholds read from `ThreatEscalationService` (which raises thresholds as Normal → Elevated → Critical based on a sliding window of threat signals).

```mermaid
flowchart TD
  Start([evaluate req]) --> User{req.user present?}
  User -->|No| DenyUser[DENY no_user]
  User -->|Yes| Score[score = req.trustScore, else evaluateScore ctx]
  Score --> Subjects[buildSubjects: user:id + role:role...]
  Subjects --> Enforce[try: enforcer.enforce for each subject]
  Enforce -->|throws| DenyErr[DENY policy_error - FAIL-CLOSED + metrics + emit policy.deny]
  Enforce -->|no rule matched| DenyCasbin[DENY casbin_no_match]
  Enforce -->|matched| Thresholds[challengeT / denyT from ThreatEscalationService]
  Thresholds --> Deny{score >= denyT?}
  Deny -->|Yes| DenyScore[DENY score_above_deny_threshold]
  Deny -->|No| Ch{score < challengeT?}
  Ch -->|Yes| Allow[ALLOW score_below_challenge_threshold]
  Ch -->|No| Challenge[CHALLENGE score_in_challenge_band]
```

---

## 7. MFA: enroll, challenge & verify

MFA is **TOTP-based**. A user first enrolls (`POST /mfa/enroll` → `MfaEnroller.createEnrollment` returns an `otpauthUri`; `POST /mfa/enroll/confirm` → `confirmEnrollment` validates the first TOTP code and persists an AES-256-GCM-encrypted secret). At request time, when policy returns CHALLENGE the user must present a valid `X-MFA-Token`; if absent or invalid the gateway creates a challenge (`MfaChallenger.createChallenge`) and replies 401 `mfa_required`. The user calls `POST /mfa/verify` with `{ challengeId, totpCode }`; `verifyTotp` checks the code against the decrypted secret and mints an MFA JWT (`typ: 'mfa'`, signed with `MFA_JWT_SECRET`, bound to `SHA-256(userId|deviceId|ip)`). That token, replayed as `X-MFA-Token`, promotes the next CHALLENGE to ALLOW.

```mermaid
sequenceDiagram
  autonumber
  participant Client
  participant Ctl as MfaController
  participant Enr as MfaEnroller
  participant Chal as MfaChallenger
  participant Mfa as MfaPromotionStage
  participant DB as Postgres / Stores

  Note over Client,DB: One-time enrollment
  Client->>Ctl: POST /mfa/enroll (Bearer)
  Ctl->>Enr: createEnrollment(userId, email)
  Enr->>DB: stash pending secret (10-min TTL)
  Enr-->>Client: { enrollmentId, otpauthUri }
  Client->>Ctl: POST /mfa/enroll/confirm { enrollmentId, totpCode }
  Ctl->>Enr: confirmEnrollment(...)
  Enr->>Enr: authenticator.verify(totpCode, pending.secret)
  Enr->>DB: save AES-GCM-encrypted secret to user_secrets
  Enr-->>Client: 200 {}

  Note over Client,DB: A data-plane request returns CHALLENGE
  Mfa->>Chal: validateMfaToken(X-MFA-Token?) -> none/invalid
  Mfa->>Chal: createChallenge(userId, ip, ja4h)
  Chal->>DB: insertChallengeIfUnderLimit (rate-limited)
  Chal-->>Mfa: { challengeId, expiresAt }
  Mfa-->>Client: 401 mfa_required + X-MFA-Challenge + verifyEndpoint

  Note over Client,DB: User completes the challenge
  Client->>Ctl: POST /mfa/verify { challengeId, totpCode } (Bearer)
  Ctl->>Chal: verifyTotp(challengeId, totpCode, userId, ip, deviceId)
  Chal->>DB: getChallenge + getEncryptedSecret -> decrypt
  Chal->>Chal: authenticator.verify -> mint MFA JWT (typ:mfa, fpHash)
  Chal->>DB: insertMfaToken(jti, fpHash, exp)
  Chal-->>Client: 200 { token (MFA JWT), expiresAt }

  Note over Client,DB: Retried request carries X-MFA-Token
  Client->>Mfa: request + Authorization + X-MFA-Token
  Mfa->>Chal: validateMfaToken(token, userId, deviceId, ip, ja4h)
  Chal->>Chal: verify signature + typ:mfa + jti + SHA-256(userId|deviceId|ip)
  Chal-->>Mfa: { ok: true }
  Note over Mfa: CHALLENGE -> ALLOW (promoted) -> continue
```

---

## 8. Proxy forward

`ProxyService.forward()` resolves the service from the path prefix via the service registry (the SSRF allowlist), rejects unknown services, then runs the resolved hostname through `DnsRebindingGuard.assertSafe()` (blocks loopback `127.0.0.0/8`, `::1`, and `169.254.169.254` on every call — no caching). Header hygiene strips `authorization`/`cookie`/`x-forwarded-for`/`host` and injects `x-user-id`/`x-roles`/`x-trust-score`/`x-ja4h`. The per-service **opossum circuit breaker wraps the full retry loop** (one `fire()` per request; one failure recorded only after all retries exhaust). The mTLS agent comes from `MtlsService.getHttpsAgent()` (mtime-cached, with a CN allowlist for server certs).

```mermaid
sequenceDiagram
  participant Stage as ProxyStage
  participant Proxy as ProxyService
  participant Reg as ServiceRegistryService
  participant Dns as DnsRebindingGuard
  participant Cb as opossum CircuitBreaker
  participant Mtls as MtlsService
  participant Down as Downstream

  Stage->>Proxy: forward(req, claims, trustScore)
  Proxy->>Reg: extractServiceName(path) + resolve(name)
  alt unknown service
    Proxy-->>Stage: NotFoundException
  end
  Reg-->>Proxy: baseUrl (allowlisted) + stripped path
  Proxy->>Dns: assertSafe(target.hostname)  [fresh lookup, no cache]
  alt loopback / 169.254.169.254
    Dns-->>Proxy: ForbiddenException
  end
  Proxy->>Mtls: getHttpsAgent()  [mtime-cached]
  Mtls-->>Proxy: https.Agent (client cert + CA)
  Proxy->>Proxy: buildProxyHeaders - strip auth/cookie/xff/host; inject x-user-id/x-roles/x-trust-score/x-ja4h
  Proxy->>Cb: fire(axiosConfig)
  Note over Cb: breaker wraps the WHOLE retry loop (backoff 100/200/400ms)
  Cb->>Down: HTTPS + mTLS request (with retries)
  Down-->>Cb: response
  Cb-->>Proxy: AxiosResponse
  Proxy->>Proxy: assertValidProxyResponse
  alt circuit open
    Proxy-->>Stage: ServiceUnavailableException
  end
  Proxy-->>Stage: { status, data }
```

---

## 9. Bootstrap & module wiring

`main.ts` creates the Nest app, runs SQL migrations, then layers global Express middleware in a fixed order: **Helmet → CORS → rate-limit**, followed by the global exception filter and validation pipe. `AppModule.configure()` then registers the DI-aware middleware (`Ja4hMiddleware` first, `GatewayMiddleware` second) for all routes. `GatewayModule` wires the prerequisite feature modules plus the 13 stage providers and assembles them in execution order through the `PIPELINE_STAGES` factory.

```mermaid
flowchart TD
  Main[main.ts bootstrap] --> Create[NestFactory.create AppModule]
  Create --> Migrate[runMigrations - sql/migrations]
  Migrate --> Helmet[1. helmet]
  Helmet --> Cors[2. enableCors]
  Cors --> Rate[3. express-rate-limit]
  Rate --> Filter[4. HttpExceptionFilter]
  Filter --> Pipe[5. ValidationPipe whitelist+transform]
  Pipe --> Listen[app.listen PORT]

  Create --> AppModule

  subgraph AppModule["AppModule (imports)"]
    direction TB
    ConfigM[ConfigAppModule]
    DbM[DbModule]
    EventsM[EventEmitterModule.forRoot]
    AuthM[AuthModule]
    SharedM[SharedModule + MtlsService]
    FpM[FingerprintModule]
    TrustM[TrustScoreModule]
    HashM[HashcashModule]
    PolicyM[PolicyModule + ThreatEscalationService]
    MfaM[MfaModule]
    DemoM[DemoMfaModule.forRoot]
    ProxyM[ProxyModule + BoPlaInterceptor]
    MetricsM[MetricsModule]
    AuditM[AuditModule]
    GatewayM[GatewayModule]
    HoneypotM[HoneypotModule - LAST]
  end

  AppModule --> Configure[configure: apply Ja4hMiddleware then GatewayMiddleware forRoutes *]

  subgraph Stages["GatewayModule PIPELINE_STAGES factory (execution order)"]
    direction TB
    Wire[public_bypass -> honeypot_bypass -> auth -> revocation -> auth_only -> trust_score -> hashcash -> policy -> mfa_promotion -> audit_allow -> proxy -> bopla_strip -> record_trust_context]
  end

  GatewayM --> Stages
```

---

## Viewing the diagrams

- **GitHub / GitLab**: Mermaid is rendered automatically in `.md` files.
- **VS Code**: Install the "Mermaid" or "Markdown Preview Mermaid Support" extension.
- **CLI**: Use [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli) to export to PNG/SVG/PDF:
  ```bash
  npx mmdc -i docs/DIAGRAMS.md -o docs/diagrams-output.pdf
  ```
- **Online**: Paste a diagram block into [mermaid.live](https://mermaid.live).

For the mechanics and rationale behind each stage see [`HARDENING_ARCHITECTURE.md`](./HARDENING_ARCHITECTURE.md); for a narrative walkthrough of a request through the pipeline see [`THESIS_PIPELINE.md`](./THESIS_PIPELINE.md). For implementation reference and local setup see [`CODEBASE.md`](./CODEBASE.md) and [`STARTUP_GUIDE.md`](./STARTUP_GUIDE.md).
