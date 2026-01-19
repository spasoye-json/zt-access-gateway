# Zero-Trust Access Gateway — Codebase & Flow Documentation

This document describes the runtime flow and responsibilities of each component in this repository. It is intended to be a “how the code actually works” companion to `README.md` and `STARTUP_GUIDE.md`.

## Table of contents

- [1. System overview](#1-system-overview)
- [2. Repository layout](#2-repository-layout)
- [3. Gateway service deep dive (`src/`)](#3-gateway-service-deep-dive-src)
  - [3.1 Entry points and bootstrap](#31-entry-points-and-bootstrap)
  - [3.2 Two planes of traffic](#32-two-planes-of-traffic)
  - [3.3 Data-plane flow (proxy pipeline)](#33-data-plane-flow-proxy-pipeline)
  - [3.4 Control-plane endpoints (controllers)](#34-control-plane-endpoints-controllers)
  - [3.5 Auth subsystem](#35-auth-subsystem)
  - [3.6 Trust scoring subsystem](#36-trust-scoring-subsystem)
  - [3.7 Policy subsystem (Casbin + risk thresholds)](#37-policy-subsystem-casbin--risk-thresholds)
  - [3.8 Proxy subsystem (allowlist + SSRF defense + retries)](#38-proxy-subsystem-allowlist--ssrf-defense--retries)
  - [3.9 mTLS subsystem](#39-mtls-subsystem)
  - [3.10 Audit logging subsystem](#310-audit-logging-subsystem)
  - [3.11 Metrics subsystem (Prometheus)](#311-metrics-subsystem-prometheus)
  - [3.12 MFA (step-up authentication)](#312-mfa-step-up-authentication)
  - [3.13 Shared utilities and error shape](#313-shared-utilities-and-error-shape)
- [4. Downstream microservices (`microservices/`)](#4-downstream-microservices-microservices)
  - [4.1 Gateway-only ingress enforcement](#41-gateway-only-ingress-enforcement)
  - [4.2 Users service](#42-users-service)
  - [4.3 Orders service](#43-orders-service)
  - [4.4 Permissions service](#44-permissions-service)
- [5. Configuration reference (env vars)](#5-configuration-reference-env-vars)
- [6. Database schema (created on startup)](#6-database-schema-created-on-startup)
- [7. Docker & deployment model](#7-docker--deployment-model)
- [8. Tests](#8-tests)
- [9. Notable caveats / paper cuts](#9-notable-caveats--paper-cuts)

---

## 1. System overview

This repository contains a NestJS gateway that enforces Zero‑Trust controls for all inbound traffic before proxying requests to internal microservices. The gateway’s primary job is to turn an inbound HTTP request into an authorization decision (**ALLOW**, **CHALLENGE**, **DENY**) and to forward only allowed requests to a downstream service over mutually authenticated TLS (mTLS).

Runtime shape:

```
Client -> Gateway (NestJS)
  - Authenticate (JWT)
  - Risk score (trust telemetry + heuristics)
  - Authorize (Casbin policies + risk thresholds)
  - Optional step-up (MFA token)
  - Proxy (allowlisted targets + mTLS)
  - Audit + Metrics

Gateway -> Microservices (NestJS)
  - Enforce gateway-only ingress (mTLS + CN allowlist)
```

This repo also includes optional observability and persistence:
- Postgres (audit logs, trust telemetry, MFA state)
- Prometheus / Grafana (metrics scraping and dashboards plumbing)

---

## 2. Repository layout

Top-level:
- `src/`: gateway service (NestJS application).
- `microservices/`: three demo microservices + the shared `GatewayOnlyGuard`.
- `policy/`: Casbin model + policy file used by the gateway.
- `tests/`: Jest integration/unit tests that live outside `src/` (additional unit tests live under `src/**/__tests__`).
- `docker-compose.yml`: local/dev stack wiring (gateway + microservices + postgres + prometheus + grafana).
- `Dockerfile`: gateway image (multi-stage build).
- `Dockerfile.microservice`: microservices image (runs all 3 in one container).
- `create-certs.sh`: dev CA + cert generator (gateway + microservices).
- `prometheus.yml`: Prometheus scrape configuration for the gateway.

Gateway source tree:
- `src/main.ts`: process entry point, creates Nest app.
- `src/app.module.ts`: root module wiring (imports feature modules, global guards).
- `src/bootstrap-app.ts`: global middleware/pipes/filters and strict config validation.
- `src/gateway/`: catch-all middleware implementing the proxy pipeline.
- `src/auth/`: JWT validation + request guards and decorators.
- `src/trust-score/`: trust score heuristics + telemetry repository.
- `src/policy/`: Casbin integration + policy admin endpoints.
- `src/proxy/`: service registry + proxy implementation.
- `src/shared/`: shared utilities (mTLS agent, request context, exception filter).
- `src/audit/`: audit logging service + persistence.
- `src/metrics/`: Prometheus metrics setup + endpoint.
- `src/mfa/`: MFA challenge/token issuance and persistence.

---

## 3. Gateway service deep dive (`src/`)

### 3.1 Entry points and bootstrap

**Process entry point**
- `src/main.ts`
  - Creates the Nest app (`NestFactory.create(AppModule, { bufferLogs: true })`).
  - Calls `validateCriticalConfig()` and `configureApp()` from `src/bootstrap-app.ts`.
  - Listens on `PORT` (default 3000).

**Root module**
- `src/app.module.ts`
  - Loads Nest’s `ConfigModule` globally from `.env` (`ConfigModule.forRoot({ isGlobal: true })`).
  - Imports feature modules: `AuthModule`, `PolicyModule`, `TrustScoreModule`, `ProxyModule`, `AuditModule`, `MetricsModule`, `GatewayModule`, `MfaModule`.
  - Registers two application-wide guards via `APP_GUARD`:
    - `JwtAuthGuard` (authentication)
    - `RolesGuard` (role-based authorization on controller endpoints)

**Global HTTP hardening and app wiring**
- `src/bootstrap-app.ts`
  - `validateCriticalConfig(configService)`:
    - Enforced only when `STRICT_CONFIG=true` or `NODE_ENV=production`.
    - Ensures JWT validation can work (`JWT_SECRET` for HS*, `JWT_JWKS_URI` for RS*/ES*).
    - Ensures outbound gateway mTLS can work (`MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH`).
    - Ensures `SERVICE_REGISTRY` parses as JSON (for proxy allowlisting).
  - `configureApp(app, configService)`:
    - Applies `helmet()`.
    - Adds a correlation middleware that sets/propagates `x-request-id`.
    - Enables CORS (`CORS_ORIGINS`) and rate limiting (`RATE_LIMIT_*`).
    - Adds a global `ValidationPipe` (DTO validation for controller endpoints).
    - Adds `HttpExceptionFilter` for consistent controller error responses.

### 3.2 Two planes of traffic

The gateway serves two classes of routes:

1) **Control-plane routes (Nest controllers)**  
   Handled by explicit controllers under `src/*/*.controller.ts`. These routes go through the global guards (`JwtAuthGuard` and `RolesGuard`) and global exception filter.

2) **Data-plane routes (proxied traffic)**  
   Everything else is intercepted by `GatewayMiddleware` and is not handled by a Nest controller. This path implements the “authenticate → score → policy → proxy” pipeline and returns its own structured JSON errors.

This split is implemented by `GatewayModule`, which applies the middleware to all routes except a small exclude list.

### 3.3 Data-plane flow (proxy pipeline)

**Where it runs**
- `src/gateway/gateway.module.ts` applies `GatewayMiddleware` to all routes (`forRoutes('*')`) and excludes:
  - `POST mfa/verify`
  - `GET metrics`
  - `ALL policy/(.*)` (covers `/policy` and `/policy/admin`)
  - `GET trust-score/calculate`
  - `GET audit/health`

**Pipeline implementation**
- `src/gateway/gateway.middleware.ts` performs (in order):

1) **Request context extraction**
   - Reads `req.method` and `req.url`.
   - Extracts:
     - `authorization` (required)
     - `x-device-id` (normalized via `resolveDeviceId`)
     - client IP (via `extractClientIp`)
     - `user-agent` (default `"unknown"`)
     - `x-mfa-token` (optional)

2) **Authenticate**
   - Calls `AuthService.validateAuthorizationHeader(authHeader)`:
     - Rejects missing header → `401 Unauthorized`.
     - Rejects invalid/expired token → `401 Unauthorized`.
   - On failure the middleware also attempts to emit an audit record with a deny decision.

3) **Trust score**
   - Calls `TrustScoreService.calculateTrustScore(userId, deviceId, ip, userAgent)`:
     - Returns `{ score, level, factors }`.
   - On trust scoring failure → `500 Internal Server Error` and audit deny.

4) **Policy evaluation**
   - Calls `PolicyService.evaluateAccess(userClaims, score, path, method)`:
     - Returns `PolicyDecision` (`ALLOW | CHALLENGE | DENY`) with a reason.
   - On policy evaluation failure → `500 Internal Server Error` and audit deny.

5) **Step-up (MFA) satisfaction**
   - If policy decision is `CHALLENGE`:
     - If `MfaService.isTokenValid(userId, x-mfa-token)` returns true, the middleware upgrades to `ALLOW`.
     - Otherwise it issues a new MFA challenge (`MfaService.initiateChallenge`) and returns:
       - `401` with `{ error: "Challenge Required", challengeId, expiresAt }`.

6) **Audit log**
   - Writes an audit record via `AuditService.logAccessDecision(...)`.
   - Audit failures are swallowed (best effort) and do not block the request.

7) **Decision handling**
   - `DENY`:
     - Records metrics and returns `403 Forbidden` with `{ error: "Forbidden", message: reason }`.
   - `CHALLENGE`:
     - Records metrics and returns the challenge response (see step 5).
   - `ALLOW`:
     - Validates path safety (`isValidPath`).
     - Routes to a service name via path prefix:
       - `/users*` -> `users-service`
       - `/orders*` -> `orders-service`
       - `/permissions*` -> `permissions-service`
       - otherwise -> `default-service`
     - Calls `ProxyService.forwardRequest(...)`.
     - Records metrics including downstream forward latency.
     - Returns the downstream status/body and forwards most response headers.

### 3.4 Control-plane endpoints (controllers)

These routes are not proxied. They are handled by Nest controllers and protected by `JwtAuthGuard` and `RolesGuard` (unless `@Public()` is used).

- `GET /audit/health` (`src/audit/audit.controller.ts`)  
  Public liveness check returning a simple string.

- `GET /trust-score/calculate` (`src/trust-score/trust-score.controller.ts`)  
  Returns the computed trust score for the authenticated user. Uses headers `x-device-id` and `user-agent` and derives IP from request.

- `GET /policy/evaluate` (`src/policy/policy.controller.ts`)  
  Admin-only endpoint that computes trust score and evaluates policy for a provided `resource` and `action`.

- Policy admin endpoints (`src/policy/policy-admin.controller.ts`) — admin-only:
  - `GET /policy/admin/rules`
  - `POST /policy/admin/rules`
  - `DELETE /policy/admin/rules`
  - `POST /policy/admin/reload`

- `GET /metrics` (`src/metrics/metrics.controller.ts`)  
  Admin-only Prometheus exposition endpoint.

- `POST /mfa/verify` (`src/mfa/mfa.controller.ts`)  
  Authenticated endpoint for verifying MFA challenges and obtaining an MFA token.

### 3.5 Auth subsystem

Primary responsibility: validate Bearer JWTs and provide role information for both controller-level guards and the proxy pipeline.

Key files:
- `src/auth/auth.service.ts`
  - Parses `Authorization: Bearer <token>`.
  - Supports:
    - HS algorithms with `JWT_SECRET`
    - RS/ES algorithms with remote JWKS (`JWT_JWKS_URI`) using `jose.createRemoteJWKSet` (cached once created).
  - Optional claim enforcement:
    - `JWT_ISSUER`, `JWT_AUDIENCE`
    - `JWT_CLOCK_TOLERANCE` (seconds)
  - Produces `UserClaims`:
    - `userId` from `payload.userId` or `sub`
    - `roles` parsed from `roles`, `realm_access.roles`, and `resource_access.*.roles`
    - `sessionId` from `sessionId`, `sid`, or `jti` (or empty string)
- `src/auth/jwt-auth.guard.ts`
  - Global guard for controller routes.
  - Bypassable via `@Public()` (`src/auth/public.decorator.ts`).
  - On success attaches `request.userClaims`.
- `src/auth/roles.guard.ts` + `src/auth/roles.decorator.ts`
  - Role gating for controller routes via `@Roles('admin', ...)`.
- `src/auth/jwt.service.ts`
  - Helper used mostly in tests to sign HS256 tokens; not the same component as `AuthService`.
- `src/auth/jwt.strategy.ts`
  - Passport “custom” strategy wrapper around `AuthService`. It exists but is not the primary enforcement mechanism (guards call `AuthService` directly).

### 3.6 Trust scoring subsystem

Primary responsibility: produce a numeric risk score (0–1) plus factor metadata, optionally backed by historical telemetry stored in Postgres.

Key files:
- `src/trust-score/trust-score.service.ts`
  - Inputs:
    - `userId`, `deviceId`, `ip`, `userAgent`
  - Uses heuristics and history:
    - Device “trust” is inferred by presence of a historical signal for `(userId, deviceId)`.
    - IP reputation uses a small set of heuristics (including “known untrusted” ranges).
    - Location fingerprinting uses the first two IPv4 octets as a coarse “geo” proxy.
    - Request frequency uses recent activity counts from telemetry.
  - Tuning env vars:
    - `TRUST_WEIGHT_BASE`, `TRUST_WEIGHT_DEVICE`, `TRUST_WEIGHT_IP`, `TRUST_WEIGHT_FREQUENCY`, `TRUST_WEIGHT_GEO`
    - `TRUST_FREQUENCY_WINDOW_MS`, `TRUST_FREQUENCY_THRESHOLD`
    - `TRUST_ACTIVITY_RETENTION_MS`
  - Writes telemetry:
    - upserts `trust_signals`
    - inserts `trust_activity`
    - deletes old `trust_activity` beyond retention
- `src/trust-score/trust-telemetry.repository.ts`
  - Postgres-backed persistence, enabled only when:
    - `DATABASE_URL` is set and usable, and
    - `NODE_ENV !== 'test'`, and
    - `DISABLE_DATABASE !== 'true'`
  - Creates tables on startup (`trust_signals` and `trust_activity`) and exposes:
    - `getSignal`, `upsertSignal`
    - `recordActivity`, `countRecentActivity`, `cleanupActivity`

### 3.7 Policy subsystem (Casbin + risk thresholds)

Primary responsibility: make an authorization decision based on static policies (Casbin RBAC-like rules) and dynamic risk thresholds.

Key files:
- `policy/model.conf`
  - Casbin matcher:
    - `keyMatch2` for path matching (`/users/:id` patterns)
    - `regexMatch` for action matching (HTTP method regexes)
- `policy/policy.csv`
  - Default rules. Example intent:
    - `role:user` can read users and list/create orders.
    - `role:admin` can access all routes with all methods.
- `src/policy/policy-evaluator.service.ts`
  - Loads Casbin enforcer on module init, defaulting to `./policy/model.conf` and `./policy/policy.csv` (overrideable via `POLICY_MODEL_PATH` and `POLICY_POLICY_PATH`).
  - Builds subjects list:
    - `user:<userId>` and `role:<role>` for each role
  - Decision process:
    1) If no subject -> `DENY` (`Unauthenticated subject`)
    2) If Casbin doesn’t allow any subject -> `DENY` (`Policy denied`)
    3) If risk score invalid -> `DENY`
    4) If `riskScore > POLICY_DENY_RISK_THRESHOLD` (default 0.8) -> `DENY`
    5) Else if `riskScore > POLICY_CHALLENGE_RISK_THRESHOLD` (default 0.5) -> `CHALLENGE`
    6) Else -> `ALLOW`
  - Supports runtime policy changes:
    - list policies, add/remove policy, reload, and best-effort persistence via `savePolicy()`.
- `src/policy/policy.service.ts`
  - Thin wrapper that exposes the evaluator to both middleware and controllers.
- Controllers:
  - `src/policy/policy.controller.ts`: admin-only “evaluate” endpoint.
  - `src/policy/policy-admin.controller.ts`: admin-only list/add/remove/reload endpoints.

### 3.8 Proxy subsystem (allowlist + SSRF defense + retries)

Primary responsibility: forward allowed requests to a downstream service in a way that prevents SSRF and enforces secure transport.

Key files:
- `src/proxy/service-registry.service.ts`
  - Parses `SERVICE_REGISTRY` as JSON: `{ "users-service": "https://host:port", ... }`.
  - Builds:
    - mapping of `serviceName -> baseUrl`
    - a hostname allowlist (derived from those URLs)
  - If no registry is configured, defaults to docker-compose style service DNS names.
- `src/proxy/proxy.service.ts`
  - Validates method, target service name, and path.
  - Performs path safety checks (blocks traversal, protocol-relative URLs, and `http(s)://` schemes in path).
  - Builds a full URL from `(baseUrl + path)` and rejects unsafe targets:
    - hostname must be allowlisted by `ServiceRegistryService`
    - URL cannot contain credentials
    - protocol must be `https:` unless `ALLOW_INSECURE_MICROSERVICE_HTTP=true`
  - Adds gateway identity headers:
    - `x-gateway-request: true`
    - `x-user-id`, `x-roles`, `x-trust-score`
  - Uses `MtlsService.createAgent(hostname)` to create an HTTPS agent with gateway client certs.
  - Resilience behavior:
    - retries: `PROXY_MAX_RETRIES`, `PROXY_RETRY_DELAY_MS`
    - circuit breaker: `PROXY_CIRCUIT_BREAKER_THRESHOLD`, `PROXY_CIRCUIT_BREAKER_TIMEOUT_MS`

### 3.9 mTLS subsystem

Primary responsibility: provide an HTTPS agent that presents gateway client certificates and validates downstream server identity.

Key file:
- `src/shared/mtls.service.ts`
  - Loads PEMs from:
    - `MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH`
  - Caches file contents by path and `mtimeMs` to avoid rereading on each request.
  - Enforces:
    - certificate validity window (not before / not after)
    - optional CN allowlist for downstream services via `MTLS_ALLOWED_SUBJECTS` (comma-separated)
    - Node/TLS hostname verification via `tls.checkServerIdentity`

Note: The gateway uses a custom config wrapper for proxy/mTLS config (`src/config/config.service.ts`) that reads directly from `process.env`. Most other modules use Nest’s `@nestjs/config` `ConfigService`.

### 3.10 Audit logging subsystem

Primary responsibility: record every decision (allow/deny/challenge) with enough metadata to support auditing and troubleshooting.

Key files:
- `src/audit/audit.service.ts`
  - Validates basic log entry shape.
  - Generates an `audit-...` id and timestamps entries.
  - Delegates persistence to `AuditRepository`.
  - Swallows errors (best-effort logging) so audit failures don’t break the gateway.
- `src/audit/audit.repository.ts`
  - Postgres-backed persistence enabled when `DATABASE_URL` is configured and DB isn’t disabled for tests.
  - Creates table `audit_logs` and an index on `request_id`.

### 3.11 Metrics subsystem (Prometheus)

Primary responsibility: provide Prometheus-format metrics on gateway behavior and latency.

Key files:
- `src/metrics/metrics.service.ts`
  - Uses `prom-client` with a per-service `Registry`.
  - Registers default Node metrics (`collectDefaultMetrics`) with prefix `zt_gateway_`.
  - Tracks:
    - total requests by decision (`zt_gateway_requests_total{decision=...}`)
    - trust score distribution (histogram)
    - trust level counts (`low|medium|high`)
    - latency histograms (evaluation, forward, total)
- `src/metrics/metrics.controller.ts`
  - Exposes `GET /metrics` (admin-only).

### 3.12 MFA (step-up authentication)

Primary responsibility: handle step-up authentication for `CHALLENGE` decisions by issuing one-time challenges and short-lived MFA session tokens.

Key files:
- `src/mfa/mfa.service.ts`
  - `initiateChallenge(...)`:
    - generates `chal-...` id and a 6-digit code
    - persists to `MfaRepository`
    - logs the code to gateway logs (development-style behavior)
    - TTL: `MFA_CHALLENGE_TTL_MS` (default 5 minutes)
  - `verifyChallenge(userId, challengeId, code)`:
    - validates challenge, marks verified
    - issues `mfa-...` token persisted in DB
    - TTL: `MFA_TOKEN_TTL_MS` (default 10 minutes)
  - `isTokenValid(userId, token)`:
    - verifies token exists, matches user, and is not expired
- `src/mfa/mfa.repository.ts`
  - Postgres persistence for:
    - `mfa_challenges`
    - `mfa_tokens`
  - Important behavior: if `DATABASE_URL` is missing, MFA operations throw (MFA is not “best-effort disabled” the way audit/trust telemetry are).
- `src/mfa/mfa.controller.ts` + `src/mfa/dto/verify-mfa.dto.ts`
  - `POST /mfa/verify` with `{ challengeId, code }` validates and issues `mfaToken`.

### 3.13 Shared utilities and error shape

- `src/shared/request-context.util.ts`
  - `extractClientIp(req)` derives IP from Express and normalizes IPv6-mapped IPv4 (`::ffff:` prefix).
  - `resolveDeviceId(value)` normalizes `x-device-id` and caps length at 128 chars.
- `src/shared/filters/http-exception.filter.ts`
  - Standardizes controller error responses as JSON:
    - `{ statusCode, error, message, path, requestId, timestamp }`

---

## 4. Downstream microservices (`microservices/`)

These services exist to demonstrate what the gateway proxies to. Each is a minimal NestJS app with in-memory data.

### 4.1 Gateway-only ingress enforcement

- `microservices/gateway-only.guard.ts`
  - Enforces that the microservice can only be called by the gateway:
    - If not TLS:
      - deny unless `ALLOW_INSECURE_MICROSERVICE_HTTP=true` *and* header `x-gateway-request: true` is present.
    - If TLS:
      - require `req.socket.authorized === true`
      - require client certificate CN in `GATEWAY_CLIENT_CERT_CNS` (or `GATEWAY_CLIENT_CERT_CN`), defaulting to `gateway`.

### 4.2 Users service

Files:
- `microservices/users-service/main.ts`: dev-friendly startup (falls back to HTTP only if `ALLOW_INSECURE_MICROSERVICE_HTTP=true`).
- `microservices/users-service/main-https.ts`: docker-friendly startup (expects certs at `/app/certs`).
- `microservices/users-service/users.controller.ts`: REST endpoints under `/users`.
- `microservices/users-service/users.module.ts`: module wiring.

Endpoints:
- `GET /users?limit=&offset=`
- `GET /users/:id`
- `POST /users`
- `PUT /users/:id`
- `DELETE /users/:id`

### 4.3 Orders service

Files:
- `microservices/orders-service/main.ts`
- `microservices/orders-service/main-https.ts`
- `microservices/orders-service/orders.controller.ts`
- `microservices/orders-service/orders.module.ts`

Endpoints:
- `GET /orders?userId=&status=&limit=&offset=`
- `GET /orders/:id`
- `POST /orders`
- `PUT /orders/:id`
- `DELETE /orders/:id`

### 4.4 Permissions service

Files:
- `microservices/permissions-service/main.ts`
- `microservices/permissions-service/main-https.ts`
- `microservices/permissions-service/permissions.controller.ts`
- `microservices/permissions-service/permissions.module.ts`

Endpoints:
- `GET /permissions?resource=&action=&limit=&offset=`
- `GET /permissions/:id`
- `POST /permissions`
- `PUT /permissions/:id`
- `DELETE /permissions/:id`

---

## 5. Configuration reference (env vars)

This is a consolidated list of the environment variables that are read by the code.

### Global / bootstrap
- `PORT`: gateway listen port (default 3000).
- `NODE_ENV`: enables production behaviors and test shortcuts.
- `STRICT_CONFIG`: when `true`, enables `validateCriticalConfig()` checks.
- `CORS_ORIGINS`: comma-separated allowlist; empty/unset means allow all.
- `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX`: rate limiting settings.

### JWT auth
- `JWT_ALGORITHM`: e.g. `HS256`, `RS256`, `ES256` (default `HS256`).
- `JWT_SECRET`: required for HS* algorithms.
- `JWT_JWKS_URI`: required for RS*/ES* algorithms.
- `JWT_ISSUER`, `JWT_AUDIENCE`: optional claim enforcement.
- `JWT_CLOCK_TOLERANCE`: clock skew tolerance in seconds (default 5).

### Policy (Casbin + risk thresholds)
- `POLICY_MODEL_PATH`, `POLICY_POLICY_PATH`: override Casbin model/policy file paths.
- `POLICY_DENY_RISK_THRESHOLD`: risk score cutoff above which access is denied (default 0.8).
- `POLICY_CHALLENGE_RISK_THRESHOLD`: risk score cutoff above which access is challenged (default 0.5).

### Trust scoring
- `TRUST_WEIGHT_BASE`, `TRUST_WEIGHT_DEVICE`, `TRUST_WEIGHT_IP`, `TRUST_WEIGHT_FREQUENCY`, `TRUST_WEIGHT_GEO`
- `TRUST_FREQUENCY_WINDOW_MS`, `TRUST_FREQUENCY_THRESHOLD`
- `TRUST_ACTIVITY_RETENTION_MS`

### Proxy / service discovery / network posture
- `SERVICE_REGISTRY`: JSON map of `{ serviceName: baseUrl }` used for an allowlist.
- `ALLOW_INSECURE_MICROSERVICE_HTTP`: allow proxying to `http:` and allow non-TLS microservice ingress (dev only).
- `PROXY_MAX_RETRIES`, `PROXY_RETRY_DELAY_MS`
- `PROXY_CIRCUIT_BREAKER_THRESHOLD`, `PROXY_CIRCUIT_BREAKER_TIMEOUT_MS`

### Gateway outbound mTLS (to microservices)
- `MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH`: gateway client cert bundle.
- `MTLS_ALLOWED_SUBJECTS`: optional comma-separated CN allowlist for downstream server certs.

### Microservice ingress mTLS (gateway-only)
- `GATEWAY_CLIENT_CERT_CNS` / `GATEWAY_CLIENT_CERT_CN`: CN allowlist for gateway client cert presented to microservices.

### Database persistence controls
- `DATABASE_URL`: Postgres connection string for audit logs, trust telemetry, and MFA persistence.
- `DISABLE_DATABASE`: disables DB-backed persistence in tests and other constrained runs.

### MFA
- `MFA_CHALLENGE_TTL_MS`: challenge lifetime (default 5 minutes).
- `MFA_TOKEN_TTL_MS`: MFA token lifetime (default 10 minutes).

---

## 6. Database schema (created on startup)

When `DATABASE_URL` is set and DB isn’t disabled, the gateway creates the following tables (idempotently):

### Audit (`src/audit/audit.repository.ts`)
- `audit_logs`
  - `id TEXT PRIMARY KEY`
  - `request_id TEXT NOT NULL`
  - `user_id TEXT NOT NULL`
  - `microservice TEXT NOT NULL`
  - `decision TEXT NOT NULL`
  - `risk_score DOUBLE PRECISION NOT NULL`
  - `policy_applied TEXT NOT NULL`
  - `metadata JSONB NOT NULL`
  - `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  - index: `idx_audit_logs_request_id(request_id)`

### Trust telemetry (`src/trust-score/trust-telemetry.repository.ts`)
- `trust_signals`
  - `user_id TEXT NOT NULL`
  - `device_id TEXT NOT NULL`
  - `last_ip TEXT`
  - `location_fingerprint TEXT`
  - `last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  - primary key: `(user_id, device_id)`
- `trust_activity`
  - `user_id TEXT NOT NULL`
  - `occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  - index: `idx_trust_activity_user_id(user_id)`

### MFA (`src/mfa/mfa.repository.ts`)
- `mfa_challenges`
  - `challenge_id TEXT PRIMARY KEY`
  - `user_id TEXT NOT NULL`
  - `code TEXT NOT NULL`
  - `expires_at TIMESTAMPTZ NOT NULL`
  - `verified_at TIMESTAMPTZ`
  - `metadata JSONB NOT NULL DEFAULT '{}'::jsonb`
- `mfa_tokens`
  - `token TEXT PRIMARY KEY`
  - `user_id TEXT NOT NULL`
  - `challenge_id TEXT NOT NULL REFERENCES mfa_challenges(challenge_id) ON DELETE CASCADE`
  - `expires_at TIMESTAMPTZ NOT NULL`
  - `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  - indexes: `idx_mfa_challenges_user_id(user_id)`, `idx_mfa_tokens_user_id(user_id)`

---

## 7. Docker & deployment model

### Local dev (no Docker)
Typical flow (also described in `STARTUP_GUIDE.md`):
1. Install dependencies: `npm install`
2. Generate certs: `./create-certs.sh`
3. Start gateway: `npm run start:dev`
4. Start microservices (3 processes), e.g. `npx ts-node microservices/users-service/main.ts`

### Docker Compose stack
- `docker-compose.yml` runs:
  - `gateway` on port 3000 (builds from `Dockerfile`)
  - microservices on 3001–3003 (builds from `Dockerfile.microservice`, but compose also defines separate `users-service`, `orders-service`, `permissions-service` services)
  - `postgres` on 5432
  - `prometheus` on 9090 (scrapes `gateway:3000`)
  - `grafana` on 3005 (maps container 3000 -> host 3005)
- `./certs` is mounted into `/app/certs` to provide PEMs.

### Images
- `Dockerfile` (gateway):
  - Multi-stage build; runtime image runs non-root and executes `node dist/main.js`.
- `Dockerfile.microservice` (microservices):
  - Builds code and runs three Node processes in the same container:
    - `node dist/microservices/users-service/main-https.js`
    - `node dist/microservices/orders-service/main-https.js`
    - `node dist/microservices/permissions-service/main-https.js`

---

## 8. Tests

Testing is via Jest (`npm test`), with tests in both `tests/` and `src/**/__tests__/`.

Key suites:
- `tests/integration/gateway-flow.e2e.spec.ts`
  - Spins up a Nest application and validates request flow using a mocked `ProxyService`.
  - Auto-skips when the environment cannot bind to a TCP port.
- `tests/unit/error-handling/error-handling.spec.ts`
  - Verifies gateway middleware error paths and responses.
- `tests/unit/microservices/gateway-only.guard.spec.ts`
  - Verifies the gateway-only ingress guard logic.
- `src/**/__tests__/*`
  - Module-level unit tests for auth, policy, trust-score, proxy, mTLS, audit, and MFA.

---

## 9. Notable caveats / paper cuts

These are behaviors that matter when operating or extending the system.

1) **Two different request IDs exist**
   - `configureApp()` sets `x-request-id` headers.
   - `GatewayMiddleware` generates a separate `requestId` used for audit/metrics payloads.
   - If you need perfect correlation, consider reusing `x-request-id` everywhere.

2) **Two configuration service types are used**
   - Most modules use Nest’s `@nestjs/config` `ConfigService`.
   - Proxy/mTLS use a custom `src/config/config.service.ts` wrapper around `process.env`.
   - This is fine but can be confusing; when adding config, ensure you update the correct service.

3) **MFA persistence is not optional**
   - Audit and trust telemetry degrade gracefully when `DATABASE_URL` is missing.
   - MFA repository throws if DB is not configured, which can break CHALLENGE flows.

4) **Microservice imports may require path-resolution support**
   - Microservice entrypoints import `GatewayOnlyGuard` using `microservices/gateway-only.guard` (non-relative specifier).
   - Depending on how you run the services (ts-node vs compiled JS), you may need a runtime path resolver (e.g., `tsconfig-paths/register`) or convert to relative imports.

