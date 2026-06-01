# Zero-Trust Access Gateway — Hardening Architecture

As-built architecture of the hardened gateway. Covers OWASP API Security 2023 compliance, the differentiating security features (JA4H fingerprinting, Hashcash PoW, shadow honeypots, BOPLA response stripping), and the fail-fast pipeline as it is implemented today.

Companion docs: [DIAGRAMS.md](./DIAGRAMS.md) is the diagram reference; [THESIS_PIPELINE.md](./THESIS_PIPELINE.md) is the narrative walkthrough of the request lifecycle.

---

## Table of contents

1. [Component map](#1-component-map)
2. [Fail-fast pipeline](#2-fail-fast-pipeline)
3. [JA4H HTTP client fingerprinting](#3-ja4h-http-client-fingerprinting)
4. [Hashcash proof of work](#4-hashcash-proof-of-work)
5. [Shadow honeypot system](#5-shadow-honeypot-system)
6. [BOPLA response interceptor](#6-bopla-response-interceptor)
7. [Trust score model (7 signals)](#7-trust-score-model-7-signals)
8. [SSRF and DNS rebinding protection](#8-ssrf-and-dns-rebinding-protection)
9. [Token revocation](#9-token-revocation)
10. [Dynamic threat escalation](#10-dynamic-threat-escalation)
11. [Audit write-ahead buffer](#11-audit-write-ahead-buffer)
12. [File structure](#12-file-structure)

---

## 1. Component map

Every module and service in the hardened gateway. Security-specific components are called out inline.

```mermaid
graph TB
  subgraph bootstrap [Bootstrap Layer]
    MainTS["main.ts\nhelmet -> CORS -> rate-limit\n+ config validation + app wiring"]
  end

  subgraph middlewareLayer [Edge + Pre-Pipeline -- Fail Fast]
    GlobalThrottler["Global Throttler (edge)\nexpress-rate-limit, IP-based"]
    JA4H["JA4H Fingerprint Middleware\nCompute fingerprint from rawHeaders"]
    HoneypotStage["Honeypot Bypass Stage\nDecoy route detection + tarpitting"]
  end

  subgraph authModule [Auth Module]
    AuthService[AuthService]
    JwtService[JwtService]
    JwtAuthGuard[JwtAuthGuard]
    RolesGuard[RolesGuard]
    TokenRevocation[TokenRevocationService]
  end

  subgraph trustModule [Trust Score Module]
    TrustScoreService[TrustScoreService]
    TrustTelemetryRepo[TrustTelemetryRepository]
    BehaviorAnomaly[BehaviorAnomalyProvider]
    TrustDecay[TrustDecayProvider]
    JA4HIntegration["Ja4hDriftProvider\nFingerprint drift detection"]
  end

  subgraph economicLayer [Economic Deterrent Layer]
    HashcashService["HashcashService\nPoW challenge/verify"]
  end

  subgraph policyModule [Policy Module]
    PolicyService[PolicyService]
    PolicyEvaluator[PolicyEvaluatorService]
    ThreatEscalation[ThreatEscalationService]
  end

  subgraph mfaModule [MFA Module -- TOTP]
    MfaChallenger[MfaChallengerService]
    MfaEnroller[MfaEnrollerService]
    UserSecretsRepo[UserSecretsRepository]
  end

  subgraph interceptorLayer [Response Layer]
    BOPLAInterceptor["BoPlaInterceptor\nRole-based field stripping\n(policy/field-policy.json)"]
  end

  subgraph proxyModule [Proxy Module]
    ProxyService[ProxyService]
    ServiceRegistry[ServiceRegistryService]
    DnsGuard["DnsRebindingGuard\nResolve-then-validate IP"]
    ResponseValidator[ResponseValidator]
  end

  subgraph auditModule [Audit Module]
    AuditService[AuditService]
    AuditRepository[AuditRepository]
  end

  subgraph metricsModule [Metrics Module]
    MetricsService[MetricsService]
    SecurityMetrics[SecurityMetricsService]
  end

  subgraph sharedModule [Shared Module]
    MtlsService[MtlsService]
    CertMonitor[CertMonitorService]
    RequestContext[RequestContextUtil]
    ExceptionFilter[HttpExceptionFilter]
    FingerprintStore["FingerprintStore\nJA4H + blacklist state"]
  end

  MainTS --> GlobalThrottler
  GlobalThrottler --> JA4H
  JA4H --> HoneypotStage

  HoneypotStage -->|Decoy hit| FingerprintStore
  FingerprintStore -->|Blacklist JA4H| TrustScoreService

  HoneypotStage -->|Clean| JwtAuthGuard
  JwtAuthGuard --> AuthService
  AuthService --> TokenRevocation

  TrustScoreService --> JA4HIntegration
  TrustScoreService --> BehaviorAnomaly
  TrustScoreService --> TrustDecay
  TrustScoreService --> TrustTelemetryRepo

  HashcashService --> TrustScoreService
  HashcashService --> MetricsService

  PolicyService --> PolicyEvaluator
  PolicyEvaluator --> ThreatEscalation

  ProxyService --> DnsGuard
  ProxyService --> MtlsService
  ProxyService --> ServiceRegistry
  ProxyService --> ResponseValidator

  AuditService --> AuditRepository

  ThreatEscalation --> AuditService
  MtlsService --> CertMonitor
```

---

## 2. Fail-fast pipeline

The full request lifecycle. Two pieces run *before* the orchestrated pipeline as NestJS/Express middleware — the global throttler (edge, `express-rate-limit` in `main.ts`) and the JA4H fingerprint middleware. The pipeline itself is **13 stages** executed in canonical order by `PipelineOrchestrator` (factory order in `gateway.module.ts`'s `PIPELINE_STAGES`). Stages are ordered so the cheapest rejections happen first, and the ALLOW audit is fail-closed (written **before** proxy forwarding).

```mermaid
flowchart TD
  A[Incoming Request] --> EDGE["Edge middleware: Global Throttler\nexpress-rate-limit, IP-based (main.ts)"]
  EDGE -->|429| EDGE_DENY[429 Too Many Requests]
  EDGE -->|Pass| B["JA4H Middleware (pre-pipeline)\nExtract fingerprint from req.rawHeaders\nAttach to req as x-ja4h"]
  B --> S1{"Stage 1: public_bypass\nIs path /health or /metrics?"}
  S1 -->|Yes| S1_BYPASS["Skip pipeline -> next()\n(controller handles it)"]
  S1 -->|No| S2{"Stage 2: honeypot_bypass\nIs route a decoy?"}
  S2 -->|Decoy Hit| S2_TRAP["Blacklist JA4H fingerprint\nAudit HONEYPOT_TRIGGERED\nReturn fake JSON payload (tarpitting)"]
  S2 -->|Real route| S3["Stage 3: auth\nValidate JWT -> UserClaims"]
  S3 -->|Invalid| S3_DENY[401 Unauthorized]
  S3 -->|Valid| S4["Stage 4: revocation\nIs JTI blacklisted?"]
  S4 -->|Revoked| S4_DENY[401 Token Revoked]
  S4 -->|Active| S5{"Stage 5: auth_only\nControl-plane path?\n(authenticated, not scored/proxied)"}
  S5 -->|Yes| S5_EXIT["Best-effort audit allow -> next()\n(short-circuit, no scoring/proxy)"]
  S5 -->|No| S6["Stage 6: trust_score\nDevice + IP + JA4H drift +\nFrequency + Anomaly + Decay"]
  S6 --> S7{"Stage 7: hashcash\nIs riskScore > high threshold?"}
  S7 -->|High risk, no solution| S7_POW["429 + X-Hashcash-Challenge header\nClient must solve SHA-256 puzzle"]
  S7 -->|Verified / not required| S8["Stage 8: policy\nCasbin RBAC + risk thresholds\n+ threat-escalation overrides"]
  S8 -->|DENY| S8_DENY[403 Forbidden]
  S8 -->|CHALLENGE| S9{"Stage 9: mfa_promotion\nValid MFA token presented?"}
  S9 -->|No| S9_MFA["401 + MFA challenge\nInitiate MFA flow"]
  S9 -->|Yes -> promote to ALLOW| S10
  S8 -->|ALLOW| S10["Stage 10: audit_allow (fail-closed)\nDurably write ALLOW audit BEFORE proxy"]
  S10 -->|Audit write failed| S10_DENY["503 Service Unavailable\n(audit-before-allow)"]
  S10 -->|Persisted| S11["Stage 11: proxy\nmTLS + DNS rebinding guard\n+ egress allowlist"]
  S11 -->|502| S11_DENY[502 Bad Gateway]
  S11 -->|Response| S12["Stage 12: bopla_strip\nStrip unauthorized fields\nper policy/field-policy.json + roles"]
  S12 --> S13["Stage 13: record_trust_context\nRecord trust context\n(only when upstreamStatus < 400)"]
  S13 --> OUT[Return sanitized response]
```

---

## 3. JA4H HTTP client fingerprinting

JA4H fingerprints the actual HTTP client implementation by examining the raw header ordering and casing. Unlike User-Agent (a trivially spoofable string), JA4H is deeply baked into the HTTP library the client uses and is nearly impossible to spoof without reimplementing the entire HTTP stack.

```mermaid
sequenceDiagram
  participant Client
  participant JA4HMiddleware as JA4H Middleware
  participant FPStore as FingerprintStore
  participant TrustService as TrustScoreService

  Client->>JA4HMiddleware: HTTP Request (with rawHeaders)

  Note over JA4HMiddleware: Access req.rawHeaders (array of<br/>[name, value, name, value, ...])<br/>Extract header names in original order<br/>Preserve original casing<br/>Hash: SHA256(method + version +<br/>ordered_header_names + accept + content-type)

  JA4HMiddleware->>JA4HMiddleware: Compute JA4H string
  JA4HMiddleware->>FPStore: Is this JA4H blacklisted?

  alt Blacklisted (honeypot catch or escalation)
    FPStore-->>JA4HMiddleware: BLOCKED
    JA4HMiddleware-->>Client: 403 (after tarpit delay)
  else Clean
    FPStore-->>JA4HMiddleware: OK
    JA4HMiddleware->>JA4HMiddleware: Attach ja4h to request context
  end

  Note over TrustService: Later in pipeline...

  TrustService->>FPStore: Get historical JA4H for (userId, sessionId)
  FPStore-->>TrustService: Previous fingerprint

  alt JA4H changed mid-session
    Note over TrustService: High-confidence signal:<br/>session hijack or bot insertion<br/>Even if IP is constant!
    TrustService->>TrustService: Add +0.3 to risk score
  else JA4H consistent
    TrustService->>TrustService: No penalty
  end
```

---

## 4. Hashcash proof of work

Instead of just blocking suspicious clients, impose an economic cost that scales with risk. Legitimate browsers solve the puzzle in milliseconds; bot farms spend hundreds of milliseconds per request, making large-scale attacks economically infeasible.

```mermaid
sequenceDiagram
  participant Client
  participant HashcashGuard as Hashcash Guard
  participant TrustService as TrustScoreService
  participant Pipeline as Rest of Pipeline

  Client->>HashcashGuard: Request (no PoW header)
  HashcashGuard->>TrustService: Get current risk score

  alt riskScore <= 0.7 (normal)
    TrustService-->>HashcashGuard: Low/Medium risk
    HashcashGuard->>Pipeline: Pass through (no PoW needed)
  else riskScore > 0.7 (suspicious)
    TrustService-->>HashcashGuard: High risk
    HashcashGuard->>HashcashGuard: Check X-Hashcash-Solution header

    alt No solution provided
      Note over HashcashGuard: Generate challenge:<br/>nonce = randomBytes(16).hex<br/>difficulty = f(riskScore)<br/>e.g. 0.7->18 bits, 0.9->22 bits
      HashcashGuard-->>Client: 429 + X-Hashcash-Challenge: nonce:difficulty
    else Solution provided
      HashcashGuard->>HashcashGuard: Verify: SHA256(nonce + solution)<br/>has 'difficulty' leading zero bits?
      alt Invalid solution
        HashcashGuard-->>Client: 429 Invalid proof of work
      else Valid solution
        Note over HashcashGuard: Cost to attacker per request:<br/>~50ms at 18 bits (human OK)<br/>~800ms at 22 bits (bot expensive)<br/>Scales with risk!
        HashcashGuard->>Pipeline: Pass through
      end
    end
  end
```

---

## 5. Shadow honeypot system

Proactive deception with zero false positives. Legitimate users never hit these routes, so any hit is a guaranteed scanner/attacker.

```mermaid
flowchart TD
  subgraph decoyRoutes [Decoy Routes -- NOT in OpenAPI spec]
    R1["/wp-login.php"]
    R2["/admin/config.json"]
    R3["/api/v1/debug"]
    R4["/.env"]
    R5["/graphql/introspection"]
    R6["/actuator/health"]
    R7["/api/v1/internal/keys"]
  end

  subgraph honeypotController [ShadowController with @Honeypot decorator]
    Handler["Handle decoy request"]
  end

  subgraph trapSequence [Trap Sequence]
    Handler --> T1["1. Extract JA4H from request context"]
    T1 --> T2["2. Blacklist JA4H in FingerprintStore\n(TTL: configurable, e.g. 24h)"]
    T2 --> T3["3. Set trust score = 1.0\nfor this session/IP"]
    T3 --> T4["4. Audit log: HONEYPOT_TRIGGERED\nwith full request metadata"]
    T4 --> T5["5. Increment zt_gateway_honeypot_triggers_total metric"]
    T5 --> T6["6. Return FAKE but realistic\nJSON response (tarpitting)"]
  end

  subgraph fakePayloads [Example Tarpit Responses]
    FP1["GET /wp-login.php\n-> fake WordPress login HTML"]
    FP2["GET /admin/config.json\n-> fake config with canary data"]
    FP3["GET /.env\n-> fake env with honeytokens"]
  end

  R1 & R2 & R3 & R4 & R5 & R6 & R7 --> honeypotController
  T6 --> FP1 & FP2 & FP3

  Note1["Key insight: legitimate users NEVER\nhit these routes. Zero false positives."]
```

---

## 6. BOPLA response interceptor

Mitigates OWASP API3:2023 (Broken Object Property Level Authorization) at the gateway level. Even if a backend microservice returns all fields, the gateway enforces data-level least privilege.

```mermaid
sequenceDiagram
  participant Downstream as Downstream Service
  participant Proxy as ProxyService
  participant BOPLA as BOPLA Interceptor
  participant Client

  Downstream-->>Proxy: Full response JSON
  Note over Downstream: Response includes ALL fields:<br/>{ id, name, email, ssn,<br/> internal_id, isAdmin,<br/> password_hash, ... }

  Proxy-->>BOPLA: Raw response + UserClaims

  BOPLA->>BOPLA: Match request path to field policy
  Note over BOPLA: Field policies define which<br/>roles can see which fields.<br/>Central config: policy/field-policy.json<br/>(micromatch patterns, first-match-wins,<br/>fail-closed empty-object default,<br/>admin-always-allow)

  alt User has role "admin"
    BOPLA->>BOPLA: Keep all fields
  else User has role "user"
    BOPLA->>BOPLA: Strip: ssn, internal_id,<br/>isAdmin, password_hash
  else User has role "viewer"
    BOPLA->>BOPLA: Keep only: id, name
  end

  BOPLA-->>Client: Sanitized response
  Note over Client: Only sees fields authorized<br/>for their role level
```

### Field policy configuration

```mermaid
flowchart LR
  subgraph fieldPolicyConfig [Field Policy Configuration]
    direction TB
    Config["policy/field-policy.json\n(central, micromatch path patterns)"]
    Example["'/users/**': {\n 'user': ['id','name','email'],\n 'viewer': ['id','name']\n}\n(admin always passes through;\n no match -> {} fail-closed)"]
    Config --> Example
  end

  subgraph interceptorLogic [Interceptor Logic]
    direction TB
    I0["0. admin role? -> return data unchanged"]
    I1["1. First-match-wins: match path to pattern"]
    I2["2. Highest-privilege matching role wins"]
    I3["3. Get allowed field set for role"]
    I4["4. Recursively strip disallowed keys"]
    I5["5. Handle arrays of objects;\n no match -> {} (fail-closed)"]
    I0 --> I1 --> I2 --> I3 --> I4 --> I5
  end

  fieldPolicyConfig --> interceptorLogic
```

---

## 7. Trust score model (7 signals)

Streamlined from the original 9 signals. User-Agent is replaced by JA4H (captures real client identity). Geolocation is replaced by behavior anomaly detection (covers impossible-travel far better than IP subnet matching).

| Signal | Type | Effect |
|---|---|---|
| Device reputation | Historical | Known device reduces risk |
| IP reputation | Historical | Trusted IP reduces risk |
| JA4H fingerprint drift | Real-time | Mid-session change = high-confidence hijack |
| Request frequency | Real-time | Burst traffic increases risk |
| Trust decay | Time-based | Idle users lose trust progressively |
| Behavior anomaly | Statistical | Deviation from profile increases risk |
| Honeypot blacklist | Terminal | Instant score = 1.0 |

```mermaid
flowchart TD
  subgraph inputs [Input Signals]
    S1[Device ID]
    S2[Client IP]
    S3["JA4H Fingerprint"]
    S4[Request Frequency]
    S5["Last Activity Time"]
    S6["Behavioral Profile"]
    S7["Honeypot Blacklist"]
  end

  subgraph terminal [Terminal Check -- first]
    S7 --> D0{"JA4H blacklisted?"}
    D0 -->|Yes| TERMINAL["Score = 1.0\nIMMEDIATE DENY\nSkip all other signals"]
    D0 -->|No| Continue[Continue to scoring]
  end

  subgraph scoring [Scoring Engine]
    Continue --> BASE["Base: 0.5"]

    S1 --> D1{Device known?}
    D1 -->|Yes| DS["-0.15"]
    D1 -->|No| DU["+0.15"]

    S2 --> D2{IP trusted?}
    D2 -->|Yes| IS["-0.15"]
    D2 -->|No| IU["+0.15"]

    S3 --> D3{"JA4H matches session?"}
    D3 -->|Yes| JS["-0.05"]
    D3 -->|No / Changed| JU["+0.30 HIGH SIGNAL"]

    S4 --> D4{Frequency normal?}
    D4 -->|Yes| FS["-0.10"]
    D4 -->|No| FU["+0.20"]

    S5 --> D5["Trust Decay\ne^(-idleMs / halfLifeMs)"]
    D5 --> DecayMult["Multiply favorable\nfactors by decay"]

    S6 --> D6["Anomaly Deviation\n0.0 to 0.4 additive"]
  end

  subgraph output [Final Score]
    BASE --> SUM
    DS & DU & IS & IU & JS & JU & FS & FU --> SUM
    DecayMult --> SUM
    D6 --> SUM
    SUM["Sum all factors"] --> CLAMP["Clamp 0.0 .. 1.0"]
    CLAMP --> LEVEL{Level}
    LEVEL -->|"< 0.3"| LOW["LOW risk\nPass through"]
    LEVEL -->|"0.3 - 0.7"| MED["MEDIUM risk\nNormal policy evaluation"]
    LEVEL -->|"> 0.7"| HIGH["HIGH risk\nHashcash PoW required"]
  end
```

---

## 8. SSRF and DNS rebinding protection

Resolves hostnames to IPs before connecting and validates the resolved IP is not in private/loopback/metadata ranges. Cross-checks against the service registry allowlist.

```mermaid
sequenceDiagram
  participant Proxy as ProxyService
  participant DNS as DnsRebindingGuard
  participant Registry as ServiceRegistryService
  participant Downstream as Downstream Service

  Proxy->>Registry: getServiceUrl("users-service")
  Registry-->>Proxy: https://users-service:3001

  Proxy->>Proxy: Construct target URL

  Proxy->>DNS: validateAndResolve(hostname)
  DNS->>DNS: dns.resolve4(hostname)
  DNS-->>DNS: Resolved IPs: [10.0.1.5]

  DNS->>DNS: Check each resolved IP against blocklist

  Note over DNS: Blocked ranges:<br/>127.0.0.0/8 (loopback)<br/>10.0.0.0/8 (RFC 1918)<br/>172.16.0.0/12 (RFC 1918)<br/>192.168.0.0/16 (RFC 1918)<br/>169.254.169.254 (cloud metadata)<br/>0.0.0.0/8<br/>::1 (IPv6 loopback)<br/>fe80::/10 (link-local)

  alt Internal network -- allowed for this gateway
    Note over DNS: Gateway legitimately talks to<br/>internal services. Check against<br/>SERVICE_REGISTRY allowlist.
    DNS->>Registry: isAllowedTarget(resolvedIP, hostname)
    alt Hostname+IP in registry
      Registry-->>DNS: ALLOWED
    else Not in registry (potential SSRF)
      Registry-->>DNS: BLOCKED
      DNS-->>Proxy: Throw SSRF_DETECTED
    end
  else Cloud metadata / loopback
    DNS-->>Proxy: Throw SSRF_DETECTED (always blocked)
  end

  Proxy->>Downstream: mTLS request to validated IP
```

---

## 9. Token revocation

Immediate invalidation of stolen or leaked JWTs via an in-memory blacklist keyed by the `jti` claim.

```mermaid
sequenceDiagram
  participant Client
  participant GW as GatewayMiddleware
  participant Auth as AuthService
  participant Revocation as TokenRevocationService

  Client->>GW: Request + Bearer JWT
  GW->>Auth: validateAuthorizationHeader(header)
  Auth-->>GW: UserClaims (with jti)

  GW->>Revocation: isRevoked(jti)
  alt Token JTI is blacklisted
    Revocation-->>GW: true
    GW-->>Client: 401 Token Revoked
  else Token is active
    Revocation-->>GW: false
    GW->>GW: Continue pipeline
  end

  Note over Revocation: Admin endpoint:<br/>POST /auth/revoke { jti }<br/>Adds to blacklist with TTL = token exp

  Note over Revocation: Blacklist entries auto-expire<br/>when the token would have expired anyway.<br/>No unbounded memory growth.
```

---

## 10. Dynamic threat escalation

`ThreatEscalationService` aggregates security signals over a bounded sliding window and **tightens the challenge/deny trust-score thresholds** as the system threat level rises (Normal -> Elevated -> Critical). Escalation is purely threshold-tightening — it does not block individual IPs or force per-user MFA. Cooldown is read-driven (no timers): once signals stop, the level steps back down one rung per elapsed cooldown window. A sticky manual override is available via the admin API.

The level is the max across per-signal-type counts: policy DENYs, invalid auth tokens, honeypot hits, and MFA rate-limits each have their own elevated/critical count thresholds. (`mfa.failed` and `audit.signal` subscribers exist but are not the primary drivers.)

The threshold numbers below are the **default values** from the config schema (`src/config/config.module.ts`); they are overridable via env (`POLICY_DENY_THRESHOLD`, `POLICY_ELEVATED_DENY_THRESHOLD`, `POLICY_CRITICAL_DENY_THRESHOLD`, and the `CHALLENGE` equivalents). Config validation enforces that critical is tighter than elevated, which is tighter than normal.

```mermaid
flowchart TD
  subgraph signals [Threat Signal Sources -- sliding window]
    S1["policy.deny\n(repeated DENYs)"]
    S2["mfa.rate_limited / mfa.failed"]
    S3["auth.invalid_token\n(invalid tokens)"]
    S4["honeypot.trigger\n(decoy hits)"]
  end

  subgraph escalation [ThreatEscalationService]
    S1 --> TE[Per-type counts; level = max across types]
    S2 --> TE
    S3 --> TE
    S4 --> TE
    TE --> TL{Threat Level}
    TL -->|Normal| NormalPolicy["Base thresholds (default)\nDENY > 0.8, CHALLENGE > 0.5"]
    TL -->|Elevated| ElevatedPolicy["Tightened thresholds (default)\nDENY > 0.6, CHALLENGE > 0.3"]
    TL -->|Critical| CriticalPolicy["Most restrictive (default)\nDENY > 0.4, CHALLENGE > 0.2"]
  end

  subgraph cooldown [Cooldown Mechanism -- read-driven, no timers]
    ElevatedPolicy --> CD["After idle >= cooldown window,\nstep down one level per elapsed window\n(Critical -> Elevated -> Normal)"]
    CriticalPolicy --> CD
    CD --> NormalPolicy
  end

  subgraph override [Admin Control]
    AdminAPI["Admin API\nsticky manual override / clear"]
    AdminAPI --> TE
  end
```

---

## 11. Audit write-ahead buffer

Guarantees ALLOW audit entries are persisted before the request is proxied (the `audit_allow` stage runs *before* `proxy`). For ALLOW decisions the write is fail-closed: `AuditService.log` retries with exponential backoff (50 -> 100 -> 200ms) and throws `AuditExhaustedException` if all retries fail, which surfaces as 503 + `Retry-After: 5`. CHALLENGE / DENY / AUTH_ONLY audits are best-effort (bounded timeout, never block).

```mermaid
flowchart TD
  A[AuditService.log] --> C{Write to DB}
  C -->|Success| D[Entry persisted]
  C -->|Failure| F["Retry with backoff\n(50 -> 100 -> 200ms)"]
  F --> C
  C -->|Retries exhausted| X[Throw AuditExhaustedException]

  subgraph critical [Critical Path Guard -- ALLOW only]
    G[ALLOW decision pending] --> H{Audit write succeeded?}
    H -->|Yes| I[Proceed to proxy forward]
    H -->|No, exhausted| J["503 Service Unavailable + Retry-After: 5\n(audit-before-allow; proxy NOT called)"]
  end

  A --> critical
```

---

## 12. File structure

The as-built tree (security-relevant files; `__tests__/` and DTO dirs elided). The pipeline is implemented as a **stage-adapter pattern**: one file per stage under `gateway/pipeline/stages/`, gathered in execution order by the `PIPELINE_STAGES` factory in `gateway.module.ts` and run by `PipelineOrchestrator`. Adding a stage = one new file + one factory entry.

```
src/
├── main.ts                           (helmet -> CORS -> rate-limit, config validation, app wiring)
├── auth/
│   ├── auth.service.ts
│   ├── token-revocation.service.ts   (JTI blacklist)
│   ├── jwt-auth.guard.ts
│   ├── roles.guard.ts
│   └── roles.decorator.ts
├── gateway/
│   ├── gateway.middleware.ts
│   ├── gateway.module.ts             (PIPELINE_STAGES factory = canonical stage order)
│   └── pipeline/
│       ├── orchestrator.ts           (runs stages in order)
│       ├── pipeline-stage.ts         (PipelineStage interface + StageOutcome)
│       ├── stage-context.ts
│       ├── stage-tokens.ts
│       ├── logging/                  (stage logger decorator + detail builders)
│       └── stages/
│           ├── public-bypass.stage.ts          (1: /health, /metrics skip pipeline)
│           ├── honeypot-bypass.stage.ts        (2: decoy detection + tarpit)
│           ├── auth.stage.ts                    (3)
│           ├── revocation.stage.ts              (4)
│           ├── auth-only-shortcircuit.stage.ts  (5: control-plane, no scoring/proxy)
│           ├── trust-score.stage.ts             (6)
│           ├── hashcash.stage.ts                (7)
│           ├── policy.stage.ts                  (8)
│           ├── mfa-promotion.stage.ts           (9)
│           ├── audit-allow.stage.ts             (10: fail-closed, BEFORE proxy)
│           ├── proxy.stage.ts                   (11)
│           ├── bopla-strip.stage.ts             (12)
│           └── record-trust-context.stage.ts    (13: only on upstreamStatus < 400)
├── fingerprint/                      (NestJS pre-pipeline middleware)
│   ├── ja4h.middleware.ts            (rawHeaders -> JA4H hash)
│   ├── ja4h.util.ts
│   └── fingerprint.store.ts          (JA4H tracking + blacklist)
├── honeypot/                         (no honeypot.guard.ts — bypass stage + controller)
│   ├── honeypot.decorator.ts         (@Honeypot())
│   ├── honeypot.constants.ts         (decoy path list)
│   ├── honeypot-responses.ts         (fake tarpit payloads)
│   ├── shadow.controller.ts          (decoy endpoints)
│   └── security-metrics.service.ts
├── hashcash/                         (no hashcash.guard.ts — service + pipeline stage)
│   ├── hashcash.service.ts           (PoW challenge/verify)
│   ├── hashcash.util.ts              (SHA-256 puzzle logic)
│   ├── hashcash-metrics.ts
│   └── used-nonce-store.ts
├── policy/
│   ├── policy-evaluator.service.ts
│   ├── threat-escalation.service.ts  (sliding-window threshold tightening)
│   └── policy-admin.controller.ts
├── proxy/
│   ├── proxy.service.ts
│   ├── service-registry.service.ts
│   ├── dns-rebinding.guard.ts
│   ├── response-validator.ts
│   └── bopla.interceptor.ts          (field stripping; reads policy/field-policy.json)
├── trust-score/
│   ├── trust-score.service.ts
│   └── providers/
│       ├── behavior-anomaly.provider.ts
│       ├── trust-decay.provider.ts
│       └── ja4h-drift.provider.ts
├── mfa/                              (TOTP-based)
│   ├── mfa-challenger.service.ts
│   ├── mfa-enroller.service.ts       (TOTP enrollment)
│   ├── enrollment.store.ts
│   ├── mfa.controller.ts
│   └── repositories/
│       └── user-secrets.repository.ts
├── audit/
│   ├── audit.service.ts              (ALLOW = fail-closed WAL w/ backoff retry)
│   └── audit-exhausted.exception.ts
├── shared/
│   ├── health.controller.ts
│   ├── cert-monitor.service.ts       (mTLS cert mtime watch)
│   └── mtls.service.ts
└── metrics/
    ├── metrics.service.ts            (security-specific metrics)
    └── metrics.controller.ts

policy/                               (repo root, not under src/)
├── model.conf                        (Casbin model)
├── policy.csv                        (Casbin RBAC rules)
└── field-policy.json                 (BOPLA: path patterns -> role -> allowed fields)
```

---

## Viewing the diagrams

- **GitHub / GitLab**: Mermaid is rendered automatically in `.md` files.
- **VS Code**: Install the "Mermaid" or "Markdown Preview Mermaid Support" extension.
- **CLI**: Use [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli) to export to PNG/SVG:
  ```bash
  npx mmdc -i docs/HARDENING_ARCHITECTURE.md -o docs/hardening-diagrams.pdf
  ```
- **Online**: Paste a diagram block into [mermaid.live](https://mermaid.live).

For diagram-only views, see [DIAGRAMS.md](./DIAGRAMS.md); for a narrative walkthrough of the request lifecycle, see [THESIS_PIPELINE.md](./THESIS_PIPELINE.md). For implementation details, see [CODEBASE.md](./CODEBASE.md) and [STARTUP_GUIDE.md](./STARTUP_GUIDE.md).
