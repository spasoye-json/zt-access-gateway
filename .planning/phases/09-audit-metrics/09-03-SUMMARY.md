---
phase: 09-audit-metrics
plan: "03"
subsystem: composition-root
tags: [app-module, e2e, audit, metrics, integration]
dependency_graph:
  requires: [09-01, 09-02]
  provides: [AuditModule+MetricsModule wired in AppModule, Phase9 e2e test coverage]
  affects: [src/app.module.ts, Phase10-GatewayMiddleware-consumer]
tech_stack:
  added: []
  patterns: [overrideProvider-for-DB-mock, createHs256Token-with-jti-for-auth-e2e]
key_files:
  modified:
    - src/app.module.ts
  created:
    - tests/integration/audit-metrics.e2e-spec.ts
decisions:
  - "Skipped honeypot tarpit trigger in MTRC-04 test; prom-client emits # HELP/# TYPE lines at zero — metric names present without seeding (avoids 2-5s tarpit delay)"
  - "Used createHs256Token with explicit jti option — JwtAuthGuard requiredClaims=['jti','sub'] rejects tokens without jti"
  - "Set PROXY_SERVICE_REGISTRY + DATABASE_URL + HASHCASH_HMAC_SECRET at top of test file before module imports — Joi schema validates at ConfigModule.forRoot() decoration time"
metrics:
  duration: "~10 minutes"
  completed: "2026-05-04T22:37:59Z"
  tasks_completed: 2
  files_changed: 2
---

# Phase 9 Plan 03: AppModule Wiring + Integration E2E Summary

**One-liner:** MetricsModule and AuditModule wired into AppModule (Pitfall 7 order), proven by 6-test e2e suite covering /metrics scrape and /audit/logs auth/role/validation paths.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Wire AuditModule and MetricsModule into AppModule | 32e9eb7 | src/app.module.ts |
| 2 | Cross-module e2e integration test | 630ee85 | tests/integration/audit-metrics.e2e-spec.ts |

## Wiring Diff (Task 1)

`src/app.module.ts` — 2 imports added, 3 lines in imports array added:

```
+import { MetricsModule } from './metrics/metrics.module';
+import { AuditModule } from './audit/audit.module';

 imports: [
   ...ProxyModule,
+  MetricsModule, // Phase 9 — registry merge (after Hashcash/Policy peers, before Honeypot last)
+  AuditModule,   // Phase 9 — WAL writer + admin query endpoint
   HoneypotModule, // Pitfall 3: stays last (Phase 2)
 ]
```

Pitfall 7 satisfied: MetricsModule comes after HoneypotModule/HashcashModule/PolicyModule so their providers are constructed first for AggregatorRegistry assembly. Pitfall 3 preserved: HoneypotModule remains last.

## E2E Test Results (Task 2)

6 tests across 2 describe blocks — all pass:

**GET /metrics (MTRC-03, MTRC-04)**
- 200 with `text/plain; charset=utf-8` content-type (no auth required — @Public())
- Body contains metric names from all 4 registries: `zt_gateway_honeypot_triggers_total`, `zt_gateway_requests_total`, `zt_gateway_stage_duration_seconds`, `zt_gateway_audit_wal_duration_seconds`

**GET /audit/logs (AUDT-05)**
- 401 with no Authorization header (JwtAuthGuard)
- 403 for non-admin JWT (RolesGuard rejects missing admin role)
- 200 with `{ items, total }` shape for admin JWT — AuditRepository.findLogs mock called
- 400 for `limit=999` (AuditLogsQueryDto @Max(200) ValidationPipe enforcement)

## Phase 9 Requirement Coverage

All Phase 9 requirement IDs are now traceable to passing tests across plans 09-00 through 09-03:

| Requirement | Plan | Test coverage |
|-------------|------|---------------|
| AUDT-01 | 09-01 | AuditRepository insert unit tests |
| AUDT-02 | 09-01 | WriteAheadBuffer WAL retry unit tests |
| AUDT-03 | 09-01 | AuditExhaustedException unit tests |
| AUDT-04 | 09-01 | record() best-effort unit tests |
| AUDT-05 | 09-03 | GET /audit/logs e2e (401/403/200/400) |
| AUDT-06 | 09-01 | AuditEntry eventType field unit tests |
| MTRC-01 | 09-02 | MetricsService counter registration unit tests |
| MTRC-02 | 09-02 | Stage histogram unit tests |
| MTRC-03 | 09-03 | GET /metrics 200 text/plain e2e |
| MTRC-04 | 09-03 | GET /metrics 4-registry aggregation e2e |
| MTRC-05 | 09-02 | JA4H blacklist gauge + fingerprint drift counter unit tests |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing jti claim in JWT signing helper**
- **Found during:** Task 2 (test run)
- **Issue:** Plan template used `SignJWT` directly without `jti`; `JwtAuthGuard` has `requiredClaims: ['jti', 'sub']` which rejects tokens without jti, causing 401 on all authenticated test cases
- **Fix:** Switched from inline `SignJWT` to `createHs256Token` from existing `src/auth/__tests__/test-keys.ts`, passing explicit `jti` option per test
- **Files modified:** `tests/integration/audit-metrics.e2e-spec.ts`

**2. [Rule 1 - Bug] Honeypot tarpit caused 5s test timeout for MTRC-04**
- **Found during:** Task 2 (test run)
- **Issue:** Plan template seeded honeypot counter via `GET /wp-login.php`; ShadowController tarpits 2-5s before responding, exceeding Jest's 5s default timeout
- **Fix:** Removed honeypot trigger — prom-client emits `# HELP` / `# TYPE` lines for zero-value counters, so metric names appear in /metrics output without any hits
- **Files modified:** `tests/integration/audit-metrics.e2e-spec.ts`

**3. [Rule 3 - Blocking] Missing required env vars for config validation**
- **Found during:** Task 2 (test run)
- **Issue:** `PROXY_SERVICE_REGISTRY` and `DATABASE_URL` are Joi-required by ConfigModule but not set in `tests/setup-e2e.ts`; `HASHCASH_HMAC_SECRET` also required
- **Fix:** Set fake-but-valid values at top of test file before any NestJS module imports (pg Pool is lazy; no real connection attempted since AuditRepository is mocked)
- **Files modified:** `tests/integration/audit-metrics.e2e-spec.ts`

## Phase 9 Status

Phase 9 is independently shippable:
- `AuditService` exported from `AuditModule` — Phase 10 GatewayMiddleware will inject it for `writeBlocking()` (ALLOW path) and `record()` (CHALLENGE/DENY path)
- `MetricsService` exported from `MetricsModule` — Phase 10 GatewayMiddleware will call `incrementRequest(decision)`, `observeStageDuration(stage, ms)`, and `observeAuditWalDuration(ms)`

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The two endpoints (`/metrics` @Public, `/audit/logs` admin-only) were already specified in plans 09-01 and 09-02; this plan only wires them into AppModule and proves they work correctly.

## Self-Check: PASSED

- src/app.module.ts: FOUND
- tests/integration/audit-metrics.e2e-spec.ts: FOUND
- commit 32e9eb7 (Task 1): FOUND
- commit 630ee85 (Task 2): FOUND
- npx tsc --noEmit: exits 0
- All 6 e2e tests: PASS
