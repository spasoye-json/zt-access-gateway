# Zero-Trust Access Gateway — Hardening Architecture

Target-state architecture for the bulletproof gateway hardening initiative. Covers OWASP API Security 2023 compliance, custom differentiating features (JA4H fingerprinting, Hashcash PoW, shadow honeypots, BOPLA interceptor), and the fail-fast pipeline design.

For the **current** architecture diagrams, see [DIAGRAMS.md](./DIAGRAMS.md).

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

Every module and service after all hardening phases are implemented. Components marked with `*` are new.

```mermaid
graph TB
  subgraph bootstrap [Bootstrap Layer]
    MainTS[main.ts]
    BootstrapApp[bootstrap-app.ts]
  end

  subgraph middlewareLayer [Pre-Auth Middleware -- Fail Fast]
    JA4H["JA4H Fingerprint Middleware *\nCompute fingerprint from rawHeaders"]
    GlobalThrottler["Global Throttler\nIP-based rate limit"]
    HoneypotGuard["Honeypot Guard *\nDecoy route detection + tarpitting"]
  end

  subgraph authModule [Auth Module]
    AuthService[AuthService]
    JwtService[JwtService]
    JwtAuthGuard[JwtAuthGuard]
    RolesGuard[RolesGuard]
    TokenRevocation["TokenRevocationService *"]
  end

  subgraph trustModule [Trust Score Module]
    TrustScoreService[TrustScoreService]
    TrustTelemetryRepo[TrustTelemetryRepository]
    BehaviorAnomaly["BehaviorAnomalyService *"]
    TrustDecay["TrustDecayEngine *"]
    JA4HIntegration["JA4H Signal Integration *\nFingerprint drift detection"]
  end

  subgraph economicLayer [Economic Deterrent Layer]
    HashcashGuard["HashcashGuard *\nPoW challenge/verify"]
  end

  subgraph policyModule [Policy Module]
    PolicyService[PolicyService]
    PolicyEvaluator[PolicyEvaluatorService]
    ThreatEscalation["ThreatEscalationService *"]
  end

  subgraph mfaModule [MFA Module]
    MfaService[MfaService]
    MfaRepository[MfaRepository]
  end

  subgraph interceptorLayer [Response Layer]
    BOPLAInterceptor["BOPLA Interceptor *\n@AuthorizedFields decorator\nRole-based field stripping"]
  end

  subgraph proxyModule [Proxy Module]
    ProxyService[ProxyService]
    ServiceRegistry[ServiceRegistryService]
    DnsGuard["DnsRebindingGuard *\nResolve-then-validate IP"]
    ResponseValidator["ResponseValidator *"]
  end

  subgraph auditModule [Audit Module]
    AuditService[AuditService]
    AuditRepository[AuditRepository]
    AuditWAL["WriteAheadBuffer *"]
  end

  subgraph metricsModule [Metrics Module]
    MetricsService[MetricsService]
    SecurityMetrics["SecurityMetrics *"]
  end

  subgraph sharedModule [Shared Module]
    MtlsService[MtlsService]
    CertMonitor["CertMonitorService *"]
    RequestContext[RequestContextUtil]
    ExceptionFilter[HttpExceptionFilter]
    FingerprintStore["FingerprintStore *\nJA4H + blacklist state"]
  end

  MainTS --> BootstrapApp
  BootstrapApp --> JA4H
  JA4H --> GlobalThrottler
  GlobalThrottler --> HoneypotGuard

  HoneypotGuard -->|Decoy hit| FingerprintStore
  FingerprintStore -->|Blacklist JA4H| TrustScoreService

  HoneypotGuard -->|Clean| JwtAuthGuard
  JwtAuthGuard --> AuthService
  AuthService --> TokenRevocation

  TrustScoreService --> JA4HIntegration
  TrustScoreService --> BehaviorAnomaly
  TrustScoreService --> TrustDecay
  TrustScoreService --> TrustTelemetryRepo

  HashcashGuard --> TrustScoreService
  HashcashGuard --> MetricsService

  PolicyService --> PolicyEvaluator
  PolicyService --> ThreatEscalation

  ProxyService --> DnsGuard
  ProxyService --> MtlsService
  ProxyService --> ServiceRegistry

  BOPLAInterceptor --> AuthService

  AuditService --> AuditWAL
  AuditWAL --> AuditRepository

  ThreatEscalation --> AuditService
  MtlsService --> CertMonitor
```

---

## 2. Fail-fast pipeline

The full request lifecycle. Every step is ordered so the cheapest rejections happen first. New steps are marked with `*`.

```mermaid
flowchart TD
  A[Incoming Request] --> B["Step 1: JA4H Middleware *\nExtract fingerprint from req.rawHeaders\nAttach to req as x-ja4h"]
  B --> C{"Step 2: Is JA4H blacklisted? *\n(honeypot or threat escalation)"}
  C -->|Blacklisted| C_DENY["403 Forbidden\n(tarpit: delay 2-5s before responding)"]
  C -->|Clean| D["Step 3: Global Throttler\nIP-based rate limit"]
  D -->|429| D_DENY[429 Too Many Requests]
  D -->|Pass| E{"Step 4: Honeypot Guard *\nIs route a decoy?"}
  E -->|Decoy Hit| E_TRAP["Blacklist JA4H fingerprint\nSet trust = 1.0 terminal\nReturn fake JSON payload\n(tarpitting)"]
  E -->|Real Route| F["Step 5: Auth Guard\nValidate JWT -> UserClaims"]
  F -->|Invalid| F_DENY[401 Unauthorized]
  F -->|Valid| G["Step 5b: Token Revocation Check *\nIs JTI blacklisted?"]
  G -->|Revoked| G_DENY[401 Token Revoked]
  G -->|Active| H["Step 6: Trust Scorer\nDevice + IP + JA4H drift +\nFrequency + Anomaly + Decay"]
  H --> I{"Step 7: Economic Guard *\nIs riskScore > highThreshold?"}
  I -->|High Risk| J{"Has valid X-Hashcash-Solution?"}
  J -->|No| J_POW["429 + X-Hashcash-Challenge header\nClient must solve SHA-256 puzzle"]
  J -->|Yes, verified| K["Step 8: Policy Guard\nCasbin RBAC + risk thresholds\n+ threat escalation overrides"]
  I -->|Normal/Low Risk| K
  K -->|DENY| K_DENY[403 Forbidden]
  K -->|CHALLENGE| K_MFA["401 + MFA Challenge\nInitiate MFA flow"]
  K -->|ALLOW| L["Step 9: Proxy Forward\nmTLS + DNS rebinding guard *\n+ egress allowlist"]
  L -->|502| L_DENY[502 Bad Gateway]
  L -->|Success| M["Step 10: BOPLA Interceptor *\nStrip unauthorized fields\nbased on UserClaims roles"]
  M --> N["Audit + Metrics\nRecord trust context"]
  N --> O[Return sanitized response]
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

  BOPLA->>BOPLA: Load field policy for endpoint
  Note over BOPLA: Field policies define which<br/>roles can see which fields.<br/>Configured via @AuthorizedFields<br/>or a central field-policy.json

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
    Config["field-policy.json or<br/>@AuthorizedFields decorator"]
    Example["'/users/:id': {\n 'admin': ['*'],\n 'user': ['id','name','email'],\n 'viewer': ['id','name']\n}"]
    Config --> Example
  end

  subgraph interceptorLogic [Interceptor Logic]
    direction TB
    I1["1. Match route to field policy"]
    I2["2. Get highest role from UserClaims"]
    I3["3. Get allowed field set for role"]
    I4["4. Recursively strip disallowed keys"]
    I5["5. Handle arrays of objects"]
    I1 --> I2 --> I3 --> I4 --> I5
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

Monitors audit log signals and automatically tightens policies when threat thresholds are crossed. Includes auto-cooldown so escalations decay over time.

```mermaid
flowchart TD
  subgraph signals [Threat Signal Sources]
    S1["Audit Log Monitor\n(repeated DENYs)"]
    S2["MFA Monitor\n(failed verifications)"]
    S3["Auth Monitor\n(invalid tokens from IP)"]
    S4["Anomaly Monitor\n(high deviation scores)"]
  end

  subgraph escalation [ThreatEscalationService]
    S1 --> TE[Threat Aggregator]
    S2 --> TE
    S3 --> TE
    S4 --> TE
    TE --> TL{Threat Level}
    TL -->|Normal| NormalPolicy["Normal thresholds\nDENY > 0.8, CHALLENGE > 0.5"]
    TL -->|Elevated| ElevatedPolicy["Tightened thresholds\nDENY > 0.6, CHALLENGE > 0.3\nForce MFA for flagged users"]
    TL -->|Critical| CriticalPolicy["Locked down\nDENY > 0.4, CHALLENGE > 0.2\nBlock flagged IPs entirely"]
  end

  subgraph cooldown [Cooldown Mechanism]
    ElevatedPolicy --> CD["Auto-decay after configurable\ncooldown period"]
    CriticalPolicy --> CD
    CD --> NormalPolicy
  end

  subgraph override [Admin Control]
    AdminAPI["POST /policy/admin/escalation\nManual override / reset"]
    AdminAPI --> TE
  end
```

---

## 11. Audit write-ahead buffer

Guarantees audit entries are persisted before allowing requests through. For ALLOW decisions, the gateway blocks the response until the audit write succeeds (audit-before-allow pattern).

```mermaid
flowchart TD
  A[AuditService.logAccessDecision] --> B["WriteAheadBuffer"]
  B --> C{Write to DB}
  C -->|Success| D[Entry persisted]
  C -->|Failure| E[Buffer entry locally]
  E --> F["Retry with exponential backoff\n(max 3 retries)"]
  F --> C

  subgraph critical [Critical Path Guard]
    G[ALLOW decision pending] --> H{Audit write succeeded?}
    H -->|Yes| I[Proceed with proxy forward]
    H -->|No, retries exhausted| J["DENY the request\n(audit-before-allow)"]
  end

  A --> critical
```

---

## 12. File structure

New files and modules after all hardening phases.

```
src/
├── auth/
│   ├── auth.service.ts              (enhanced: issuer/audience validation)
│   ├── token-revocation.service.ts  * NEW
│   ├── jwt.service.ts
│   ├── jwt-auth.guard.ts
│   └── ...
├── gateway/
│   ├── gateway.middleware.ts         (rewritten: 10-step fail-fast pipeline)
│   └── gateway.module.ts
├── fingerprint/                      * NEW MODULE
│   ├── fingerprint.module.ts
│   ├── ja4h.middleware.ts           * (rawHeaders -> JA4H hash)
│   ├── fingerprint.store.ts         * (JA4H tracking + blacklist)
│   └── __tests__/
│       └── ja4h.middleware.spec.ts
├── honeypot/                         * NEW MODULE
│   ├── honeypot.module.ts
│   ├── honeypot.decorator.ts        * (@Honeypot())
│   ├── honeypot.guard.ts            * (decoy route detection)
│   ├── shadow.controller.ts         * (fake endpoints + tarpit)
│   └── __tests__/
│       └── honeypot.guard.spec.ts
├── hashcash/                         * NEW MODULE
│   ├── hashcash.module.ts
│   ├── hashcash.guard.ts            * (PoW challenge/verify)
│   ├── hashcash.util.ts             * (SHA-256 puzzle logic)
│   └── __tests__/
│       └── hashcash.guard.spec.ts
├── policy/
│   ├── threat-escalation.service.ts * NEW
│   └── ...
├── proxy/
│   ├── dns-rebinding.guard.ts       * NEW
│   ├── response-validator.ts        * NEW
│   └── ...
├── trust-score/
│   ├── trust-score.service.ts       (enhanced: JA4H + decay + anomaly)
│   ├── behavior-anomaly.service.ts  * NEW
│   └── ...
├── interceptors/                     * NEW DIRECTORY
│   ├── bopla.interceptor.ts         * (field stripping)
│   ├── authorized-fields.decorator.ts * (@AuthorizedFields)
│   └── field-policy.json            * (route->role->fields map)
├── audit/
│   ├── write-ahead-buffer.ts        * NEW
│   └── ...
├── shared/
│   ├── health.service.ts            * NEW
│   ├── cert-monitor.service.ts      * NEW
│   └── ...
└── metrics/
    └── metrics.service.ts           (enhanced: security-specific metrics)
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

For the current (pre-hardening) architecture, see [DIAGRAMS.md](./DIAGRAMS.md). For implementation details, see [CODEBASE.md](./CODEBASE.md) and [STARTUP_GUIDE.md](./STARTUP_GUIDE.md).
