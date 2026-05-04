---
phase: 09-audit-metrics
plan: "02"
subsystem: metrics
tags: [metrics, prometheus, prom-client, registry-merge, seam-methods, tdd, event-emitter]
dependency_graph:
  requires: [09-00]
  provides: [MetricsService, MetricsController, MetricsModule, PipelineStage, STAGE_LABELS]
  affects: [Phase 10 GatewayMiddleware (seam methods), GET /metrics scrape endpoint]
tech_stack:
  added: []
  patterns: [private-prom-client-registry, registry-merge-per-call, class-level-public-decorator, raw-response-text-plain, onevent-subscriber]
key_files:
  created:
    - src/metrics/metrics.service.ts
    - src/metrics/metrics.controller.ts
    - src/metrics/metrics.module.ts
  modified:
    - src/metrics/__tests__/metrics.service.spec.ts
    - src/metrics/__tests__/metrics.controller.spec.ts
decisions:
  - "Registry.merge() called per getAggregatedMetrics() invocation (D-01) — no cached AggregatorRegistry; metric objects are by reference so O(4) per scrape, always current"
  - "@Public() at class level on MetricsController (mirrors HealthController) — single route makes method-level redundant; Reflector test targets class"
  - "audit_failures_total and audit_wal_duration_seconds live in MetricsService (D-03) to prevent AuditModule ↔ MetricsModule circular dependency"
  - "@OnEvent('audit.record_failed') on MetricsService.onAuditRecordFailed() — D-05 seam; AuditService.record() emits the event, MetricsService increments counter without importing MetricsModule from AuditModule"
  - "EventEmitterModule.forRoot() imported in MetricsModule so @OnEvent subscriber is discoverable even when MetricsModule is loaded outside AppModule in tests"
metrics:
  duration: ~10min
  completed: "2026-05-05"
---

# Phase 09 Plan 02: MetricsModule Implementation Summary

**One-liner:** MetricsService with 7 private-registry metrics, per-call Registry.merge() across 4 registries, 7 typed seam methods, @OnEvent D-05 audit bridge, and MetricsController @Public GET /metrics; 19 tests passing.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | MetricsService — 7 metrics, merge logic, seam methods | 6a704e0 | metrics.service.ts, metrics.service.spec.ts |
| 2 | MetricsController — @Public GET /metrics, text/plain | 931c4da | metrics.controller.ts, metrics.controller.spec.ts |
| 3 | MetricsModule — imports Honeypot/Hashcash/Policy, exports MetricsService | 9fd9de2 | metrics.module.ts |

## Source Files Created (3 source + 2 specs)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/metrics/metrics.service.ts` | 7-metric private Registry + 4-registry merge + 7 seam methods | `MetricsService`, `PipelineStage`, `STAGE_LABELS` |
| `src/metrics/metrics.controller.ts` | Prometheus scrape endpoint @Public GET /metrics | `MetricsController` |
| `src/metrics/metrics.module.ts` | NestJS module wiring | `MetricsModule` |

## 7 Metrics Confirmed (D-02, D-03)

| Metric Name | Type | Labels | Purpose |
|-------------|------|--------|---------|
| `zt_gateway_requests_total` | Counter | `decision` (allow/challenge/deny) | MTRC-01 gateway request totals |
| `zt_gateway_stage_duration_seconds` | Histogram | `stage` (8 labels, D-09) | MTRC-02 pipeline stage latency |
| `zt_gateway_token_revocations_total` | Counter | — | MTRC-04 token revocations |
| `zt_gateway_ja4h_blacklist_size` | Gauge | — | MTRC-05 JA4H blacklist size |
| `zt_gateway_fingerprint_drift_total` | Counter | — | MTRC-05 mid-session drift events |
| `zt_gateway_audit_wal_duration_seconds` | Histogram | — | D-10 WAL write latency (all retries) |
| `zt_gateway_audit_failures_total` | Counter | — | D-10 WAL exhaustion + D-05 record() failures |

## 8 Stage Labels + Buckets (D-09)

Stage labels: `ja4h`, `blacklist`, `auth`, `revocation`, `trust_score`, `hashcash`, `policy`, `proxy`

Buckets (both histograms): `[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1]`

## 7 Seam Methods (Phase 10 injection surface)

- `incrementRequest(decision: 'allow' | 'challenge' | 'deny'): void`
- `observeStageDuration(stage: PipelineStage, durationSeconds: number): void`
- `observeAuditWalDuration(durationSeconds: number): void`
- `incrementAuditFailure(): void`
- `incrementTokenRevocation(): void`
- `setJa4hBlacklistSize(n: number): void`
- `incrementFingerprintDrift(): void`

## 4-Registry Merge (D-01, MTRC-03)

`getAggregatedMetrics()` calls `Registry.merge([securityMetrics.getRegistry(), hashcashMetrics.registry, policyMetrics.registry, this.registry])` on every invocation. No cached AggregatorRegistry — post-init mutations are immediately visible on next scrape (verified by test).

## D-05 Event Seam

`@OnEvent('audit.record_failed') onAuditRecordFailed()` increments `zt_gateway_audit_failures_total`. AuditService.record() emits `audit.record_failed` via EventEmitter2 on DB errors — no circular module dependency (AuditModule never imports MetricsModule).

## Test Coverage

| Spec File | Tests | Status |
|-----------|-------|--------|
| metrics.service.spec.ts | 16 (metrics x9, merge x5, @OnEvent x1, isolation x1) | PASS |
| metrics.controller.spec.ts | 3 (@Public metadata, status 200, Content-Type) | PASS |
| **Total** | **19** | **All passing** |

## Deviations from Plan

None — plan executed exactly as written.

## Note on AppModule Wiring

MetricsModule wiring into AppModule + cross-module e2e tests happen in Plan 09-03. The MetricsModule exports MetricsService and is ready for AppModule import.

## Self-Check: PASSED

Files verified:
- src/metrics/metrics.service.ts: FOUND
- src/metrics/metrics.controller.ts: FOUND
- src/metrics/metrics.module.ts: FOUND
- src/metrics/__tests__/metrics.service.spec.ts: FOUND (0 it.todo calls)
- src/metrics/__tests__/metrics.controller.spec.ts: FOUND (0 it.todo calls)

Commits verified:
- 6a704e0: feat(09-02): implement MetricsService with 7 metrics, 4-registry merge, 7 seam methods
- 931c4da: feat(09-02): implement MetricsController with @Public GET /metrics, text/plain
- 9fd9de2: feat(09-02): wire MetricsModule (imports Honeypot/Hashcash/Policy, exports MetricsService)
