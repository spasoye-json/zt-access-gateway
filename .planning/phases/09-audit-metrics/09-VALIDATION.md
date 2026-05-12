---
phase: 9
slug: audit-metrics
status: finalized
nyquist_compliant: true
validated_at: 2026-05-12
wave_0_complete: true
created: 2026-05-04
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | jest 30.x + ts-jest |
| **Config file** | `package.json` (jest section) |
| **Quick run command** | `npx jest src/audit src/metrics --passWithNoTests` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx jest src/audit src/metrics --passWithNoTests`
- **After every plan wave:** Run `npm test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 9-01-01 | 01 | 2 | AUDT-01 | T-09-01-03 | audit_logs table has correct schema (incl. event_type for AUDT-06) | unit | `npx jest src/audit/__tests__/audit.repository.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-02 | 01 | 2 | AUDT-02 / AUDT-03 / AUDT-04 | T-09-01-04 | writeBlocking retries 3x then throws AuditExhaustedException | unit | `npx jest src/audit/__tests__/audit.service.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-03 | 01 | 2 | AUDT-03 / D-05 | T-09-01-05 | record() catches errors, logs warning, emits 'audit.record_failed', never throws | unit | `npx jest src/audit/__tests__/audit.service.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-04 | 01 | 2 | AUDT-04 / AUDT-05 | T-09-01-02 | GET /audit/logs returns paginated results for admin | unit | `npx jest src/audit/__tests__/audit.controller.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-05 | 01 | 2 | AUDT-05 | T-09-01-01 | AuditLogsQueryDto validates decision enum + limits | unit | `npx jest src/audit/__tests__/audit.controller.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-06 | 01 | 2 | AUDT-06 | — | AuditModule wires AuditService + EventEmitterModule (audit.record_failed seam) | unit | `npx jest src/audit/__tests__/audit.module.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-01-07 | 01 | 2 | AUDT-06 | T-09-01-03 | AuditEntry.eventType persists to event_type column (HONEYPOT_TRIGGERED queryable) | unit | `npx jest src/audit/__tests__/audit.repository.spec.ts` | ✅ W0 stub created in 09-00 Task 4 | ⬜ pending |
| 9-02-01 | 02 | 2 | MTRC-01 | T-09-02-03 | zt_gateway_requests_total counter increments per decision | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-02-02 | 02 | 2 | MTRC-02 | T-09-02-02 | zt_gateway_stage_duration_seconds histogram has 8 stage labels | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-02-03 | 02 | 2 | MTRC-03 | T-09-02-01 | GET /metrics returns text/plain Prometheus format; @Public() at class level | unit | `npx jest src/metrics/__tests__/metrics.controller.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-02-04 | 02 | 2 | MTRC-04 | — | zt_gateway_token_revocations_total counter present | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-02-05 | 02 | 2 | MTRC-05 / MTRC-04 | T-09-02-04 | Registry.merge() across all 4 registries | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-02-06 | 02 | 2 | D-05 | — | @OnEvent('audit.record_failed') subscriber increments zt_gateway_audit_failures_total | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ W0 stub created in 09-00 Task 5 | ⬜ pending |
| 9-03-01 | 03 | 3 | AUDT-05 / MTRC-03 | T-09-03-01..05 | AppModule e2e: GET /metrics public, GET /audit/logs admin-gated | e2e | `npx jest --config tests/jest-e2e.json tests/integration/audit-metrics.e2e-spec.ts` | n/a (created in Plan 03) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Wave 0 stub spec files are created by Plan 09-00 Tasks 4 (audit) and 5 (metrics). All RED stubs are in place; Wave 0 is COMPLETE.

- [x] `src/audit/__tests__/audit.service.spec.ts` — stubs for AUDT-01, AUDT-03, AUDT-04, AUDT-06 (incl. eventType + audit.record_failed event seam)
- [x] `src/audit/__tests__/audit.repository.spec.ts` — stubs for AUDT-02 / AUDT-05 (DB tests under describeDb guard; incl. event_type column)
- [x] `src/audit/__tests__/audit.controller.spec.ts` — stubs for AUDT-05 (Reflector roles metadata + DTO validation)
- [x] `src/audit/__tests__/audit.module.spec.ts` — stubs for AUDT-06 (module wiring incl. EventEmitterModule)
- [x] `src/metrics/__tests__/metrics.service.spec.ts` — stubs for MTRC-01, MTRC-02, MTRC-04, MTRC-05 + @OnEvent('audit.record_failed') subscriber (D-05)
- [x] `src/metrics/__tests__/metrics.controller.spec.ts` — stubs for MTRC-03

> **Reconciliation note:** Earlier drafts referenced a separate `src/audit/__tests__/write-ahead-buffer.spec.ts` for AUDT-02/AUDT-03 retry tests. The plans consolidate WAL retry tests into `audit.service.spec.ts` (where `writeBlocking` lives) — `write-ahead-buffer.spec.ts` is NOT created. Row 9-01-02 above references `audit.service.spec.ts` accordingly.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| audit_logs DB migration runs cleanly | AUDT-01 | Requires live Postgres | Run `docker-compose up db`, run `psql -f sql/migrations/006_audit_logs.sql`, verify `audit_logs` table exists with all columns (incl. `event_type`) and 3 indexes |

> Registry.merge runtime aggregation (MTRC-03) is now AUTOMATED via `tests/integration/audit-metrics.e2e-spec.ts` (Plan 09-03 Task 2) — no longer a manual verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (consolidated into audit.service.spec.ts; no orphan write-ahead-buffer.spec.ts reference)
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter
- [x] `wave_0_complete: true` set in frontmatter

**Approval:** approved (post-revision 2026-05-04)
