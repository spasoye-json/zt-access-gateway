# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Development
npm run start:dev          # Hot-reload dev server
npm run build              # Compile TypeScript → dist/

# Testing
npm test                   # Run all unit tests
npm run test:watch         # Watch mode
npm run test:cov           # Coverage report (→ ./artifacts/coverage)
npm run test:e2e           # End-to-end tests (uses tests/jest-e2e.json)

# Run a single test file
npx jest src/auth/__tests__/auth.service.spec.ts

# Lint (auto-fix)
npm run lint

# Full stack (gateway + 3 microservices + Postgres + Prometheus + Grafana)
docker-compose up --build
```

## Documentation map

- **[`CONTEXT.md`](./CONTEXT.md)** — ubiquitous-language glossary. The canonical vocabulary for the domain. Read this before naming anything.
- **[`docs/adr/`](./docs/adr/)** — Architecture Decision Records. The *why* behind hard-to-reverse, non-obvious choices. Check here before "fixing" something that looks deliberate.
- **[`docs/HARDENING_ARCHITECTURE.md`](./docs/HARDENING_ARCHITECTURE.md)** / **[`DIAGRAMS.md`](./docs/DIAGRAMS.md)** — the *how* (mechanics, diagrams).
- **[`docs/CODEBASE.md`](./docs/CODEBASE.md)** / **[`docs/STARTUP_GUIDE.md`](./docs/STARTUP_GUIDE.md)** — implementation reference and local setup.

## Architecture

This is a **Zero-Trust Access Gateway** built with NestJS. Every inbound request passes through a fixed pipeline before being proxied to a downstream microservice:

```
Request → Auth Guard → Gateway Middleware → [TrustScore → Policy → Audit → Metrics] → Proxy / Challenge / Deny
```

### Request Pipeline (GatewayMiddleware)

1. **Auth** (`src/auth/`) — validates Bearer JWT (HS256/RS256/ES256, JWKS-backed). Extracts `UserClaims`.
2. **Trust Score** (`src/trust-score/`) — computes a 0.0–1.0 risk score from device reputation, IP history, geolocation, and request frequency. Stored in Postgres (`trust_signals`, `trust_activity`).
3. **Policy Evaluator** (`src/policy/`) — Casbin RBAC (`policy/model.conf` + `policy/policy.csv`). Tests `user:<id>` and `role:<role>` subjects. Returns **ALLOW / CHALLENGE / DENY** based on score thresholds.
4. **MFA** (`src/mfa/`) — CHALLENGE promotes to ALLOW if a valid MFA token is presented. MFA tokens are a separate JWT (signed with `MFA_JWT_SECRET`) validated against IP + device + location fingerprint.
5. **Proxy** (`src/proxy/`) — forwards allowed requests via mTLS to the target microservice. Strips auth headers; injects `x-user-id`, `x-roles`, `x-trust-score`. Has circuit breaker, exponential-backoff retry, and SSRF protection.
6. **Audit** (`src/audit/`) — best-effort persistence of every decision to `audit_logs` in Postgres.
7. **Metrics** (`src/metrics/`) — Prometheus counters/histograms exposed at `/metrics`.

### Module Map

| Module | Path | Responsibility |
|---|---|---|
| `auth` | `src/auth/` | JWT validation, `JwtAuthGuard`, `RolesGuard`, `@Public()` decorator |
| `policy` | `src/policy/` | Casbin enforcer, policy admin REST API |
| `trust-score` | `src/trust-score/` | Risk scoring heuristics, `TrustTelemetryRepository` |
| `proxy` | `src/proxy/` | mTLS forwarding, service registry, circuit breaker |
| `audit` | `src/audit/` | `audit_logs` persistence |
| `metrics` | `src/metrics/` | Prometheus integration |
| `mfa` | `src/mfa/` | Challenge lifecycle, `mfa_challenges` / `mfa_tokens` tables |
| `gateway` | `src/gateway/` | `GatewayMiddleware` — orchestrates the full pipeline |
| `shared` | `src/shared/` | `MtlsService` (cert caching + CN validation), exception filters, `RequestContext` |
| `config` | `src/config/` | Typed wrappers over `process.env` |

### Key Design Decisions

- **Trust context is only recorded on ALLOW** (after proxy succeeds) to prevent a CHALLENGE bypass attack.
- **Service registry** (`PROXY_SERVICE_REGISTRY` env var, JSON map) is the SSRF allowlist — only registered services can be proxied to.
- **mTLS cert caching** uses `mtime` to invalidate without restart.
- **Audit logging is best-effort** — failures are caught and logged as warnings; they never block a request.
- **Rate limiting, Helmet, CORS** are applied in `src/main.ts`.

### Testing Patterns

- Unit tests live in `__tests__/` subdirectories within each module.
- Integration/e2e tests live in `tests/integration/`.
- `tests/setup.ts` configures Jest globals; network tests auto-skip when TCP binding is unavailable (CI sandboxes).
- `ProxyService` is mocked in app-level tests to avoid real network calls.

### Environment

Key env vars (see `.env.example` for full list):

| Var | Purpose |
|---|---|
| `JWT_SECRET` | HMAC secret (HS256) or `JWT_PUBLIC_KEY` for RS256/ES256 |
| `JWKS_URI` | Remote JWKS endpoint (optional) |
| `POLICY_CHALLENGE_RISK_THRESHOLD` | Score above which → CHALLENGE (default 0.5) |
| `POLICY_DENY_RISK_THRESHOLD` | Score above which → DENY (default 0.8) |
| `PROXY_SERVICE_REGISTRY` | JSON map of `serviceName → baseUrl` |
| `MTLS_CA_CERT_PATH` / `MTLS_CLIENT_CERT_PATH` / `MTLS_CLIENT_KEY_PATH` | mTLS certificates |
| `MTLS_ALLOWED_SUBJECTS` | Comma-separated CN allowlist for server certs |
| `MFA_JWT_SECRET` | Secret for signing MFA challenge tokens |
| `DATABASE_URL` | Postgres connection string |

## Project

**Zero-Trust Access Gateway**

A hardened NestJS zero-trust access gateway with a 10-step fail-fast pipeline. Every inbound request passes through JA4H fingerprinting, honeypot detection, authentication, token revocation check, 7-signal trust scoring, hashcash PoW (for high-risk requests), Casbin policy evaluation, MFA challenge, mTLS proxy forwarding, and BOPLA response field stripping — with audit WAL and security-specific Prometheus metrics. Being rebuilt from scratch using TDD.

**Core Value:** Every request is verified, scored, and authorized before reaching any downstream service — no implicit trust, no shortcuts.

### Constraints

- **Tech stack**: NestJS + TypeScript — non-negotiable, existing scaffold in place
- **Testing**: TDD — write test first, then implementation. Real Postgres via Docker for DB tests. Real libraries (jose, casbin, https) from day one.
- **Build order**: Layer-by-layer following pipeline dependency chain. Each module fully tested before moving to the next.
- **Database**: PostgreSQL for all persistent state
- **Observability**: Prometheus-compatible metrics

## Technology Stack

## Languages
- TypeScript 5.7.3 - All source code and build tooling
- ES2023 - Compilation target for Node.js modern features
## Runtime
- Node.js 18+ (from Dockerfile: `node:18-alpine`)
- npm - Lockfile: `package-lock.json` present
## Frameworks
- NestJS 11.0.1 - Backend framework (previously 10.0.0)
- @nestjs/common 11.0.1 - Core decorators and utilities
- @nestjs/core 11.0.1 - Application factory and module system
- @nestjs/config 4.0.3 - Environment variable management
- @nestjs/platform-express 11.0.1 - Express adapter
- Jest 30.0.0 - Unit and integration test runner (configured in `package.json` jest section)
- ts-jest 29.2.5 - TypeScript transpiler for Jest
- @nestjs/testing 11.0.1 - NestJS-specific testing utilities
- supertest 7.0.0 - HTTP assertion library for e2e tests
- @nestjs/cli 11.0.0 - NestJS code generation and project scaffolding
- @nestjs/schematics 11.0.0 - Schematics for code generation
- ts-node 10.9.2 - TypeScript execution for Node.js
- ts-loader 9.5.2 - Webpack TypeScript loader
- tsconfig-paths 4.2.0 - Path alias resolution at runtime
## Key Dependencies
- jose 6.2.2 - JWT creation/validation (HS256, RS256, ES256 algorithms)
- reflect-metadata 0.2.2 - Decorator metadata reflection (required by NestJS)
- rxjs 7.8.1 - Reactive streams (NestJS dependency)
- casbin 5.45.0 - RBAC policy engine (policy evaluation)
- pg 8.16.3 - PostgreSQL client driver (trust signals, audit logs, MFA tokens)
- axios 1.13.2 - HTTP client (service proxying)
- helmet 7.2.0 - HTTP security headers middleware
- express-rate-limit 7.0.0 - Rate limiting middleware
- prom-client 15.1.3 - Prometheus metrics client
- class-validator 0.14.3 - Input validation decorators
- class-transformer 0.5.1 - DTO transformation
- lodash 4.17.21 - Utility library
- passport-jwt 4.0.1 - JWT authentication strategy
- passport-custom 1.1.1 - Custom authentication strategy
- @nestjs/passport 11.0.5 - NestJS Passport integration
- @nestjs/axios 4.0.1 - NestJS wrapper for axios
## Configuration
- `.env` file for environment variables (not committed)
- Typed wrapper: `ConfigService` in `src/config/` (from previous commits)
- Environment-based strict validation for production
- TypeScript: `tsconfig.json` with ES2023 target, strict null checks
- NestJS CLI config: `nest-cli.json` with `deleteOutDir: true`
- Jest config inline in `package.json`
- ESLint: `eslint.config.mjs` (migrated to flat config format)
- Prettier: `.prettierrc` with single quotes and trailing commas
## Platform Requirements
- Node.js 18+ (or modern LTS)
- npm for dependency management
- Port 3000 (default gateway port, configurable via `PORT` env var)
- Node.js 18+ minimal
- Postgres 15+ (from docker-compose)
- mTLS certificates (CA cert, client cert, client key)
- Prometheus (optional, for metrics)
- Grafana (optional, for visualization)
## Build Process
- TypeScript compilation: `nest build` → outputs to `./dist/`
- Entry point: `src/main.ts` → `dist/main.js`
- Source maps enabled for debugging
- Test coverage directory: `./coverage/` (configured as `coverageDirectory` in package.json)

## Conventions

## Naming Patterns
- Controllers: `{entity}.controller.ts` (e.g., `app.controller.ts`)
- Services: `{entity}.service.ts` (e.g., `app.service.ts`)
- Modules: `{entity}.module.ts` (e.g., `app.module.ts`)
- Specs/Tests: `{entity}.spec.ts` or `{entity}.test.ts` (co-located with source)
- Entry point: `main.ts`
- Controllers: `{Entity}Controller` (PascalCase + "Controller" suffix)
- Services: `{Entity}Service` (PascalCase + "Service" suffix)
- Modules: `{Entity}Module` (PascalCase + "Module" suffix)
- camelCase (e.g., `getHello()`, `bootstrap()`)
- Getter methods: `get{Property}()`
- Query methods: start with `get` (e.g., `getHello()`)
- Action methods: start with verb (e.g., `create`, `update`, `delete`)
- camelCase for all local variables and parameters
- Constructor injections: camelCase with `private readonly` prefix (e.g., `private readonly appService: AppService`)
- Avoid single-letter variable names except in loops
- PascalCase (e.g., `UserClaims`, `TrustTelemetry`)
- Prefix interfaces with `I` or use implicit contract (project uses implicit)
- DTOs: `{Entity}Dto` suffix (e.g., `CreateUserDto`)
- UPPER_SNAKE_CASE for enum values and exported constants
- PascalCase for enum type names
## Code Style
- Prettier 3.4.2 enforces formatting
- Single quotes enabled in `.prettierrc`
- Trailing commas on all multi-line constructs (`"trailingComma": "all"`)
- Auto-fix on save or use `npm run format`
- ESLint with TypeScript support (typescript-eslint)
- ESLint config: `eslint.config.mjs`
- Key rules:
- Run `npm run lint` to fix violations automatically
- Target: ES2023
- Strict nullchecks enabled
- No implicit any allowed in strict mode (but noImplicitAny: false in base config)
- Decorators and metadata emission enabled (NestJS requirement)
## Import Organization
- Not currently configured in codebase
- Use relative imports (e.g., `./service` for sibling, `../shared/utils` for parent)
- One import statement per module
- Destructure named imports on single line
- Use absolute paths for third-party, relative for local code
## Decorator Usage
- Module-level: `@Module()` - declares imports, controllers, providers
- Class-level: `@Controller()`, `@Injectable()` - marks class role
- Method-level: `@Get()`, `@Post()`, `@Put()`, `@Delete()` - HTTP verbs
- Parameter-level: `@Param()`, `@Query()`, `@Body()` - request binding
- Custom decorators: `@Public()`, `@Roles()` - project-specific auth decorators
- Decorators immediately precede the decorated item (no blank lines)
- Stack decorators vertically for readability
## Dependency Injection
- Constructor injection via private readonly properties
- Services are automatically injected by NestJS container
- No manual instantiation (new keyword)
## Error Handling
- Use NestJS built-in exceptions (`HttpException`, `BadRequestException`, `UnauthorizedException`, etc.)
- Thrown exceptions are caught by NestJS exception filters and returned as HTTP responses
- Validation errors via `ValidationPipe` return 400 Bad Request automatically
- Controllers throw HTTP exceptions; they propagate to filters
- Services may throw exceptions or return error objects (project-specific)
- Global exception filter handles unhandled errors
- `GatewayMiddleware` catches errors and logs them as warnings (best-effort pattern)
- Failures in audit logging never block requests
- Policy evaluation returns decision enum (ALLOW/CHALLENGE/DENY) rather than throwing
## Logging
- Use `console.log()` for info, `console.warn()` for warnings, `console.error()` for errors
- Logging in middleware/services for request lifecycle tracking
- Environment-based log levels (e.g., production vs development)
- Best-effort logging - errors are caught and logged as warnings, never blocking requests
- Audit logging is best-effort; failures logged as warnings
- Trust signal recording only on ALLOW (after proxy succeeds)
## Comments
- Explain "why", not "what"
- Document non-obvious design decisions (e.g., "Trust context only recorded on ALLOW to prevent CHALLENGE bypass")
- Complex algorithms or business rules
- Security considerations
- Commenting obvious code (e.g., `// Get the user` above `const user = ...`)
- Commented-out code blocks (use git history instead)
- Redundant comments that repeat the code
- Document public API functions and classes
- Use `@param`, `@returns`, `@throws` tags
- Not consistently used in starter files, but recommend for shared modules
## Function Design
- Single responsibility principle
- Easier to test and reason about
- Callback/promise chains should be extracted into separate functions
- 3 or fewer parameters preferred
- Use object destructuring for multiple related params
- Avoid boolean parameters (use named options object instead)
- Return meaningful data or void
- Throw exceptions for error cases (NestJS pattern)
- Methods returning Observable for async operations (RxJS)
- Mark functions `async` when they await promises
- Avoid returning promises directly without await; use `async`
- NestJS automatically subscribes to Observables
## Module Design
- Export classes that are the main interface (e.g., `AppService`, `AppController`)
- Export types/interfaces for other modules to import
- Private/internal helpers don't need explicit export (keep in same module)
- Not currently used (project is small starter phase)
- When modules grow, consider `index.ts` files for cleaner imports
## Visibility
- `private readonly` for injected dependencies (immutable, private to class)
- `public` for methods (default if not specified)
- `private` for internal helper methods
- Avoid `protected` unless inheritance is planned
## Async Patterns
- NestJS works with both via `async`/`await` and Observables
- Controllers can return Promises or Observables directly
- Services typically return Promises or Observables based on data source
- Let exceptions propagate to NestJS exception filters
- Use try/catch for cleanup or logging, then re-throw

## Architecture

## Pattern Overview
- Fixed request processing pipeline enforced through NestJS middleware
- Every inbound request validated and risk-scored before proxying downstream
- Layered decision-making: Auth → TrustScore → Policy → MFA → Proxy
- Best-effort audit logging without blocking requests
- Prometheus metrics exposure for observability
## Layers
- Purpose: Accept inbound requests and configure global middleware
- Location: `src/main.ts`
- Contains: Application bootstrap, Helmet/CORS/rate-limiting config, exception filters
- Depends on: NestJS core, ConfigService
- Used by: Express/Node runtime
- Purpose: Validate Bearer JWT tokens (HS256/RS256/ES256) with optional JWKS support
- Location: `src/auth/`
- Contains: `AuthService` (token validation), `JwtAuthGuard` (NestJS guard), `JwtService` (signing), `UserClaims` interface
- Depends on: jose (JWT library), ConfigService
- Used by: GatewayMiddleware, policy evaluation
- Purpose: Compute 0.0–1.0 risk score from device/IP/geolocation/request frequency
- Location: `src/trust-score/`
- Contains: `TrustScoreService`, `TrustTelemetryRepository` (Postgres-backed)
- Depends on: Database (Postgres), RequestContext utilities
- Used by: GatewayMiddleware for policy decisions
- Purpose: RBAC authorization using Casbin, map score thresholds to decisions
- Location: `src/policy/`
- Contains: `PolicyEvaluatorService` (Casbin enforcer), `PolicyService` (admin API), policy model/CSV from `policy/` directory
- Depends on: Casbin, TrustScoreService
- Used by: GatewayMiddleware, returns ALLOW/CHALLENGE/DENY
- Purpose: Challenge verification and MFA token management
- Location: `src/mfa/`
- Contains: `MfaService` (challenge/token lifecycle), `MfaRepository` (Postgres), `MfaController` (challenge endpoint)
- Depends on: Database, AuthService (for MFA JWT signing)
- Used by: GatewayMiddleware to promote CHALLENGE → ALLOW
- Purpose: mTLS forwarding to target microservices with SSRF protection
- Location: `src/proxy/`
- Contains: `ProxyService` (HTTP forwarding, circuit breaker, retries), `ServiceRegistryService` (SSRF allowlist), `MtlsService` (cert caching)
- Depends on: HttpService (@nestjs/axios), Shared.MtlsService, ConfigService
- Used by: GatewayMiddleware for ALLOW decisions
- Purpose: Persist access decisions to `audit_logs` table in Postgres
- Location: `src/audit/`
- Contains: `AuditService` (log decisions), `AuditRepository` (DB access), `AuditController` (health check)
- Depends on: Database
- Used by: GatewayMiddleware, fires after decisions
- Purpose: Prometheus counters/histograms for gateway decisions
- Location: `src/metrics/`
- Contains: `MetricsService` (counter/histogram management), `MetricsController` (GET /metrics)
- Depends on: prom-client (or similar)
- Used by: GatewayMiddleware, external monitoring
- Purpose: Cross-cutting utilities (mTLS, context, exception filters)
- Location: `src/shared/`
- Contains: `MtlsService` (cert loading/caching), `RequestContext` utilities (IP extraction), `HttpExceptionFilter` (error responses)
- Depends on: fs, crypto, ConfigService
- Used by: ProxyService, GatewayMiddleware, all modules
- Purpose: Typed wrappers over `process.env`
- Location: `src/config/`
- Contains: `ConfigService`, `ConfigModule`
- Depends on: @nestjs/config
- Used by: All services
## Data Flow
- **Trust signals** (`trust_signals` table): Device fingerprints, IP ranges, geolocation data
- **Trust activity** (`trust_activity` table): Historical access patterns, anomaly flags
- **MFA challenges** (`mfa_challenges` table): Challenge state, OTP/WebAuthn details
- **MFA tokens** (`mfa_tokens` table): JWT MFA tokens bound to IP/device/location
- **Audit logs** (`audit_logs` table): Complete access decision history
- **Policies** (`policy/policy.csv`): Casbin RBAC rules; model in `policy/model.conf`
## Key Abstractions
- Purpose: Standardized JWT token payload
- Examples: `src/auth/auth.service.ts` (interface definition)
- Pattern: Extracted once in AuthService, threaded through all layers
- Purpose: Unified decision object { decision: ALLOW | DENY | CHALLENGE, reason, score? }
- Examples: `src/policy/policy-evaluator.service.ts`
- Pattern: Returned by PolicyEvaluatorService, consumed by GatewayMiddleware
- Purpose: Extract and validate client IP, device ID, user-agent
- Examples: `src/shared/request-context.util.ts`
- Pattern: Utilities for header parsing; no stateful object
- Purpose: Load certificates from disk, cache by mtime, create HTTPS agents
- Examples: `src/shared/mtls.service.ts`
- Pattern: Singleton service with cert caching; invalidates on file change
## Entry Points
- Location: `src/main.ts`
- Triggers: Node process starts
- Responsibilities: Create NestJS app, validate config, configure middleware stack, listen on PORT
- Location: `src/gateway/gateway.middleware.ts`
- Triggers: Any HTTP request to the gateway (except excluded paths)
- Responsibilities: Orchestrate full pipeline (auth → trust → policy → mfa → proxy → audit → metrics)
- Location: `src/policy/policy-admin.controller.ts`
- Triggers: PUT/DELETE /policy/admin (restricted to admin role)
- Responsibilities: Add/remove Casbin rules at runtime
- Location: `src/metrics/metrics.controller.ts`
- Triggers: GET /metrics (Prometheus scrape)
- Responsibilities: Serialize counters/histograms in Prometheus format
- Location: `src/mfa/mfa.controller.ts` (POST /mfa/verify)
- Triggers: User completing MFA challenge
- Responsibilities: Validate MFA token, return JWT for retried request
- Location: `src/trust-score/trust-score.controller.ts` (GET /trust-score/calculate)
- Triggers: Manual risk assessment or debugging
- Responsibilities: Calculate and return current trust score for device
## Error Handling
- **Auth errors:** Return 401 (Unauthorized), logged as DENY audit events
- **Policy errors:** Return 403 (Forbidden), logged as DENY audit events
- **MFA errors:** Return 403 (Forbidden), return challenge details
- **Proxy errors:** Return upstream status code or 502 (Bad Gateway) if unreachable
- **Audit/metrics failures:** Log as warnings, never block request (best-effort)
- Catches NestJS HttpException instances
- Returns standardized JSON response { error, message, statusCode }
- Does not leak internal details (safe for production)
- AuthService throws UnauthorizedException → caught, logged, response sent
- ProxyService throws ServiceUnavailableException → caught, logged as 502
- All layer errors are wrapped and returned with requestId for debugging
## Cross-Cutting Concerns
- NestJS Logger used in each service (RequestId injected where relevant)
- All auth failures, proxy errors, config validation logged at warn/error level
- Audit table serves as audit trail for security events
- Input validation in each service (token format, path validation, URL validation)
- NestJS ValidationPipe for DTO validation (POST bodies)
- Header validation in GatewayMiddleware (type checking, length limits)
- Bearer token extraction in AuthService
- JWT verification with jose (supports HS256/RS256/ES256)
- JWKS endpoint support for remote key rotation
- User roles extracted from JWT claims, used by RolesGuard
- Casbin RBAC model (user/role subjects, resource/action evaluation)
- Risk-based decisions (thresholds on trust score)
- MFA promotion (CHALLENGE → ALLOW with valid MFA token)
- Route-level @Roles() decorator (metrics → admin, policy → admin)
- x-request-id is generated/propagated in `src/gateway/pipeline/build-stage-context.ts` (falls back to `randomUUID()`)
- Included in all logs and responses
- Helps trace requests through system


## Agent skills

### Issue tracker

Issues live as GitHub issues at `spasoye-json/zt-access-gateway`; use the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` at repo root, `docs/adr/` tree. Both created lazily by `/grill-with-docs`. See `docs/agents/domain.md`.
