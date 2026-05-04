---
phase: 08-proxy-bopla
plan: "02"
subsystem: proxy-service
tags:
  - proxy
  - circuit-breaker
  - opossum
  - retry
  - mtls
  - header-sanitization
  - tdd-green
dependency_graph:
  requires:
    - "08-00: opossum CJS transform fix, AppConfigService Phase 8 getters, RED stubs"
    - "08-01: ServiceRegistryService, DnsRebindingGuard, assertValidProxyResponse"
  provides:
    - "ProxyService: full forward path (registry → DNS guard → opossum → retry → response validator)"
    - "Per-service CircuitBreaker map (D-02)"
    - "Header sanitization: STRIP_HEADERS set + x-gateway-* prefix drop (PRXY-02)"
    - "Exponential backoff retry (D-12) wrapped by opossum (D-11)"
  affects:
    - "08-03: BoPlaInterceptor consumes AxiosResponse from ProxyService.forward()"
    - "08-04: ProxyModule wires ProxyService into NestJS DI"
tech_stack:
  added: []
  patterns:
    - "import CircuitBreaker = require('opossum') — TypeScript import-equals-require for CJS interop (Pitfall 1)"
    - "opossum wraps full retry loop — single fire() per request, single failure recorded after exhausted retries (D-11)"
    - "axios mocked at jest.mock('axios') level; sleep mocked for instant backoff tests"
    - "Direct constructor injection in tests (no TestingModule) per PATTERNS.md"
key_files:
  created:
    - src/proxy/proxy.service.ts
  modified:
    - src/proxy/__tests__/proxy.service.spec.ts
decisions:
  - "MtlsService.getHttpsAgent() is async in the actual implementation (not sync as stated in plan interface description); ProxyService awaits it before building axiosConfig — deviation documented"
  - "Retry on 502/503/504 only; 500/501 not in RETRIABLE_STATUSES (Pitfall 3 — side-effect safety)"
  - "opossum wraps full retry loop so transient failures resolved by retry do not prematurely trip breaker (D-11)"
  - "One CircuitBreaker per registered service in onModuleInit; per-service isolation (D-02)"
metrics:
  duration: "~8 minutes"
  completed_date: "2026-05-04"
  tasks_completed: 1
  files_changed: 2
---

# Phase 8 Plan 02: ProxyService Summary

ProxyService implemented TDD GREEN — composes ServiceRegistryService + DnsRebindingGuard + MtlsService + opossum + raw axios into the full forward path with per-service circuit breakers, D-12 exponential backoff retry, and PRXY-02 header sanitization.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | ProxyService with circuit breakers, retry loop, header sanitization | 30b9faa | src/proxy/proxy.service.ts, src/proxy/__tests__/proxy.service.spec.ts |

## What Was Built

### ProxyService (`src/proxy/proxy.service.ts`)

`@Injectable` implementing `OnModuleInit`. Full pipeline in `forward(req, claims, trustScore)`:

1. `registry.extractServiceName(path)` → serviceName (throws `NotFoundException` if null)
2. `registry.resolve(serviceName)` → baseUrl (throws `NotFoundException` for unknown services — PRXY-06)
3. `registry.stripPrefix(path)` → forwardedPath
4. `new URL(forwardedPath, baseUrl)` → target URL (SSRF-safe via registry allowlist — T-08-02-06)
5. `dnsGuard.assertSafe(target.hostname)` → throws `ForbiddenException` (PRXY-07, PRXY-08)
6. `mtls.getHttpsAgent()` → httpsAgent (awaited — actual impl is async)
7. `breaker.fire(axiosConfig)` → opossum wraps `executeWithRetry` (D-11)
8. `assertValidProxyResponse(response)` → throws on 5xx or non-JSON Content-Type (PRXY-09)

**Header sanitization (PRXY-02):**
- STRIP_HEADERS set: `authorization`, `cookie`, `x-forwarded-for`, `host`, `content-length`
- Prefix strip: any `x-gateway-*` from inbound caller dropped
- Injected: `x-user-id`, `x-roles`, `x-trust-score`, `x-gateway-request: true`

**Retry loop (D-10, D-12):**
- Retries on: `ECONNREFUSED`, `ETIMEDOUT`, `ECONNRESET`, HTTP 502/503/504
- Does NOT retry: 4xx, 500, 501 (Pitfall 3 — side-effect safety)
- Backoff: 100ms → 200ms → 400ms across max 3 retries (configurable via `PROXY_MAX_RETRIES`)
- Retry loop is the opossum action function — one `fire()` per request, one failure recorded after retries exhausted (D-11)

**Circuit breakers (D-02, D-03):**
- One `CircuitBreaker` per service in `registry.listServices()` created in `onModuleInit()`
- Options: `volumeThreshold`, `errorThresholdPercentage`, `resetTimeout` from `AppConfigService`
- OPEN state → `ServiceUnavailableException` via `CircuitBreaker.isOurError(err)` detection
- Per-service isolation: service-A breaker open does not affect service-B

## Test Results

| File | Tests | Result |
|------|-------|--------|
| proxy.service.spec.ts | 24 | GREEN |
| service-registry.service.spec.ts | 10 | GREEN (unchanged) |
| dns-rebinding.guard.spec.ts | 9 | GREEN (unchanged) |
| response-validator.spec.ts | 6 | GREEN (unchanged) |
| bopla.interceptor.spec.ts | 17 todo | remain RED (Wave 3) |
| **Total proxy suite** | **66** | **GREEN** |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] MtlsService.getHttpsAgent() is async, not sync**
- **Found during:** Task 1 implementation
- **Issue:** The plan's interface description stated `getHttpsAgent(): https.Agent` (synchronous), but the actual `src/shared/mtls.service.ts` implementation returns `Promise<https.Agent>`. Using it synchronously would have returned a pending Promise instead of the agent.
- **Fix:** Added `await` before `this.mtls.getHttpsAgent()` in `forward()`. The `httpsAgent` variable is now correctly typed as `https.Agent`.
- **Files modified:** src/proxy/proxy.service.ts
- **Commit:** 30b9faa

### Tests Added

The Wave 0 stub file had 23 `it.todo` entries. This plan replaced all of them with 24 real `it()` tests (one additional test for `DnsRebindingGuard.assertSafe` rejection). Zero `it.todo` remain in proxy.service.spec.ts.

## Known Stubs

None. ProxyService is fully implemented. All method paths are wired to real dependencies.

## Threat Flags

No new network endpoints or auth paths introduced. All STRIDE mitigations from the plan's threat register are implemented:

| Threat ID | Mitigation | Status |
|-----------|------------|--------|
| T-08-02-01 | STRIP_HEADERS set + x-gateway-* prefix drop | Implemented |
| T-08-02-02 | MtlsService.getHttpsAgent provides client cert | Implemented |
| T-08-02-03 | opossum volumeThreshold + per-service breakers | Implemented |
| T-08-02-04 | RETRIABLE_STATUSES = {502, 503, 504} only | Implemented |
| T-08-02-05 | assertValidProxyResponse guards non-JSON | Implemented (plan 08-01) |
| T-08-02-06 | URL from registry + DnsRebindingGuard.assertSafe | Implemented |
| T-08-02-07 | Unbounded body — accepted (documented) | Accepted |
| T-08-02-08 | axios timeout: 30000ms | Implemented |

## Self-Check: PASSED

- `src/proxy/proxy.service.ts`: FOUND
- `src/proxy/__tests__/proxy.service.spec.ts`: FOUND (24 tests, 0 it.todo)
- commit 30b9faa: FOUND
- `npx tsc --noEmit`: exits 0
- `npx jest src/proxy/`: 66 tests, all GREEN
