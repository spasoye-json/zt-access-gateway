# Zero-Trust Access Gateway (NestJS)

An opinionated backend gateway that enforces Zero-Trust principles for a set of demo microservices (users/orders/permissions). Every inbound request is authenticated, risk-scored, policy-evaluated, and proxied over secure channels before reaching an internal service. Audit events and metrics are emitted for every decision.

## Current Capabilities

| Area | Details |
| --- | --- |
| Authentication | Centralized Bearer parsing and JWT verification supporting HS256 secrets or RS/ES algorithms via JWKS. Issuer/audience enforcement, length/sanity checks, and a global guard protect every route by default. |
| Policy Engine | Casbin RBAC model (`policy/model.conf`, `policy/policy.csv`) evaluates `subject → resource → action` permissions, exposes admin APIs to list/add/remove/reload policies, and layers risk thresholds to return **ALLOW / CHALLENGE / DENY**. |
| Trust / Risk | Heuristic scoring with configurable weights backed by telemetry stored in Postgres tracks per-device history, IP fingerprints, and request frequency to produce LOW/MEDIUM/HIGH outcomes plus factor metadata. |
| Gateway Pipeline | Middleware enforces `Auth → Trust Score → Policy → Proxy → Audit → Metrics`. Helmet, CORS, rate limiting, validation pipes, and structured error responses are wired globally during bootstrap. Request IDs propagate via `x-request-id`. |
| Proxy & mTLS | Forwards allowed traffic to internal microservices with identity headers/trust score, uses a configurable service registry allowlist, retries transient failures, and includes a lightweight circuit breaker. Validates targets and URL safety, enforces HTTPS by default, and loads mTLS material from configurable paths. |
| Observability | Audit logs persist to Postgres when `DATABASE_URL` is set (best-effort logging otherwise). Prometheus metrics (via `prom-client`) are exposed at `/metrics`, and Docker Compose ships with Prometheus/Grafana for dashboards. |
| Tests | Jest coverage for auth, policy evaluator, proxy, trust score, audit logging, gateway error handling, and end-to-end request flow. Tests auto-skip integration cases when sockets cannot be opened in CI sandboxes. |

## Architecture at a Glance

```
[Client] --HTTPS--> [Gateway (NestJS)]
   ├─ AuthService (JWT/JWKS validation, guards)
   ├─ TrustScoreService (context/risk heuristics)
   ├─ PolicyEvaluatorService (Casbin + risk thresholds)
   ├─ ProxyService (mTLS forwarding + SSRF protection)
   ├─ AuditService (decision logging)
   └─ MetricsService (Prometheus-style counters)

Downstream demo services:
  - users-service (port 3001)
  - orders-service (port 3002)
  - permissions-service (port 3003)
```

## Repository Layout

```
.
├── src/
│   ├── auth/          # JwtStrategy, guard, helpers
│   ├── gateway/       # Request middleware & orchestration
│   ├── policy/        # Policy module + Casbin evaluator
│   ├── trust-score/   # Risk scoring heuristics
│   ├── proxy/         # Secure forwarding & mTLS helpers
│   ├── audit/         # Audit logging service/controller
│   ├── metrics/       # Metrics aggregation + endpoint
│   ├── shared/        # Cross-cutting services (JWT, mTLS, filters)
│   └── bootstrap-app.ts # Global middleware setup
├── microservices/     # Demo Nest services (users/orders/permissions)
├── policy/            # Casbin model + policy CSV
├── tests/             # Jest unit + integration suites
├── Dockerfile         # Gateway container
├── Dockerfile.microservice
└── docker-compose.yml # Gateway + demo services + observability stack
```

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+
- For Docker-based workflows: Docker + Docker Compose

### Install dependencies

```bash
npm install
```

### Environment configuration

Copy `.env.example` (if present) or edit `.env` directly. Key variables:

| Variable | Description |
| --- | --- |
| `PORT` | Gateway HTTP port (default `3000`) |
| `JWT_ALGORITHM` | e.g. `HS256`, `RS256`, `ES256`. Defaults to `HS256`. |
| `JWT_SECRET` | Shared secret for HS algorithms. Required when using HS*. |
| `JWT_JWKS_URI` | JWKS endpoint when using RS/ES algorithms. |
| `JWT_ISSUER` / `JWT_AUDIENCE` | Optional claim enforcement. |
| `CORS_ORIGINS` | Comma-separated allowlist; blank means allow all. |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | Rate limiter settings. |
| `MTLS_CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH` | Paths to gateway cert material for outbound mTLS. |
| `GATEWAY_CLIENT_CERT_CNS` | Comma-separated CN allowlist for gateway client certs accepted by microservices. |
| `POLICY_MODEL_PATH`, `POLICY_POLICY_PATH` | Override Casbin files if needed. |
| `DATABASE_URL` | Postgres connection string used for audit logs and trust telemetry (gateway degrades gracefully if not provided). |
| `SERVICE_REGISTRY` | JSON map of `{ "service-name": "https://hostname:port" }` used as the allowlist for downstream targets. |
| `PROXY_MAX_RETRIES` / `PROXY_RETRY_DELAY_MS` | Retry count and base delay (ms) for transient downstream failures. |
| `PROXY_CIRCUIT_BREAKER_THRESHOLD` / `PROXY_CIRCUIT_BREAKER_TIMEOUT_MS` | Failure count and cool-off window for the circuit breaker. |
| `TRUST_WEIGHT_BASE`, `TRUST_WEIGHT_DEVICE`, `TRUST_WEIGHT_IP`, `TRUST_WEIGHT_FREQUENCY`, `TRUST_WEIGHT_GEO` | Weights applied to trust-score components (defaults sum around 1). |
| `TRUST_FREQUENCY_WINDOW_MS` / `TRUST_FREQUENCY_THRESHOLD` | Sliding window + threshold for request frequency anomaly detection. |
| `TRUST_ACTIVITY_RETENTION_MS` | Retention for trust telemetry activity records. |
| `ALLOW_INSECURE_MICROSERVICE_HTTP` | Set `true` to allow HTTP-only microservices (dev only). |
| `STRICT_CONFIG` | Set `true` or use `NODE_ENV=production` to fail fast on missing critical config. |
| `DISABLE_DATABASE` | Set `true` to disable Postgres-backed persistence in tests. |

### Run the gateway (dev mode)

```bash
npm run start:dev
```

Gateway boots on `http://localhost:3000` with hot reload.

### Start demo microservices

Each microservice can be launched with `ts-node`:

```bash
./create-certs.sh
npx ts-node microservices/users-service/main.ts
npx ts-node microservices/orders-service/main.ts
npx ts-node microservices/permissions-service/main.ts
```

> Certificates in `certs/` enable mTLS during development. Microservices validate the gateway client certificate CNs via `GATEWAY_CLIENT_CERT_CNS`. To run microservices without HTTPS, set `ALLOW_INSECURE_MICROSERVICE_HTTP=true` (dev only).

### Docker Compose

Run the full stack (gateway + demo services + Postgres + Prometheus + Grafana):

```bash
docker-compose up --build
```

- Gateway: `http://localhost:3000`
- Grafana: `http://localhost:3005` (default creds `admin/admin`)
- Prometheus: `http://localhost:9090`
- Postgres: exposed on `localhost:5432` (used for audit logs + trust telemetry)

## Testing

```bash
npm test
```

- Unit suites cover auth, policy, proxy, trust-score, audit, and gateway error handling.
- Integration suite (`tests/integration/gateway-flow.e2e.spec.ts`) spins up the Nest app and exercises end-to-end flows. In sandboxed CI environments where binding to a TCP port isn’t allowed, the tests auto-skip but still report success.
- Coverage artifacts are emitted in `coverage/`.

## Request Walkthrough

1. **Auth Guard** extracts Bearer tokens, validates them (secret or JWKS), and attaches `userClaims` to the request context.
2. **Gateway Middleware** logs a request ID, performs extra schema/path validation, and invokes the Trust Score service.
3. **Trust Score** returns a numeric score + factor metadata.
4. **Policy Evaluator** checks Casbin rules for either `user:<id>` or `role:<role>` subjects. If authorized, the score is compared to challenge/deny thresholds.
5. **Proxy Service** forwards allow-listed requests to the matching microservice, appending `x-user-id`, `x-roles`, and `x-trust-score` headers and using mTLS certificates from the config.
6. **Audit + Metrics** log every decision (best-effort) and update Prometheus metrics for observability.

## Policy Administration API

Authenticated operators can manage rules at runtime:

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/policy/admin/rules` | List loaded Casbin policies (`subject`, `resource`, `action`). |
| `POST` | `/policy/admin/rules` | Add a policy binding (`{ subject, resource, action }`). |
| `DELETE` | `/policy/admin/rules` | Remove a policy binding (body mirrors POST). |
| `POST` | `/policy/admin/reload` | Reload policies from the configured model/policy files. |

Changes are persisted via the Casbin adapter (file-based by default) so they survive restarts.

## Metrics & Observability

- `/metrics` exposes Prometheus text format (counters, histograms, and default Node metrics). Scrape it directly or via the bundled Prometheus container.
- Audit logs are inserted into `audit_logs` in Postgres when `DATABASE_URL` is configured. The gateway falls back to best-effort logging if the database is unavailable.
- Trust telemetry tables (`trust_signals`, `trust_activity`) capture per-user/device history that feeds into risk scoring, providing a paper trail for anomalous decisions.

## Roadmap / Future Enhancements

- Ship opinionated Prometheus/Grafana dashboards (latency, decision mix, trust telemetry) and bundle alerts/SLOs.
- Enhance Trust Score with behavioral baselines, device reputation feeds, or ML-backed anomaly detection.
- Add policy versioning / approvals plus persistence beyond flat files (e.g., database adapter or OPA integration).
- Implement certificate rotation automation for mTLS (step-ca integration) and richer service discovery integrations.
- Expand test coverage with fuzzing & security suites (JWT tampering, SSRF, policy bypass attempts).

## License

MIT
