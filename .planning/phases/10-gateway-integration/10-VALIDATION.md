---
phase: 10
slug: gateway-integration
status: finalized
nyquist_compliant: true
validated_at: 2026-05-12
wave_0_complete: false
created: 2026-05-09
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | jest 30.x (NestJS testing) |
| **Config file** | `package.json` (jest section) for unit; `tests/jest-e2e.json` for e2e |
| **Quick run command** | `npx jest src/gateway/__tests__/gateway.middleware.spec.ts --runInBand` |
| **Full suite command** | `npm test && npm run test:e2e` |
| **Estimated runtime** | ~45 seconds (unit) / ~90 seconds (e2e w/ Postgres) |

---

## Sampling Rate

- **After every task commit:** Run `npx jest <changed-spec> --runInBand`
- **After every plan wave:** Run `npm test`
- **Before `/gsd-verify-work`:** Full suite (unit + e2e) must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 10-01-* | 01 | 1 | GTWY-01..09 (constants) | — | Path-based bypass allowlists | unit | `npx jest src/gateway/__tests__/public-paths.spec.ts` | ❌ W0 | ⬜ pending |
| 10-02-* | 02 | 1 | GTWY-09 | T-10-02 | Honeypot path bypass | unit | `npx jest src/honeypot/__tests__/honeypot.constants.spec.ts` | ❌ W0 | ⬜ pending |
| 10-03-* | 03 | 1 | GTWY-08 | — | MFA stage label + counter | unit | `npx jest src/metrics/__tests__/metrics.service.spec.ts` | ✅ | ⬜ pending |
| 10-04-* | 04 | 2 | GTWY-01..09 | T-10-* | Middleware orchestration | unit | `npx jest src/gateway/__tests__/gateway.middleware.spec.ts` | ❌ W0 | ⬜ pending |
| 10-05-* | 05 | 3 | GTWY-04 | T-10-05 | APP_GUARD removal, route-level guards | integration | `npm run test:e2e -- gateway-integration` | ❌ W0 | ⬜ pending |
| 10-06-* | 06 | 3 | GTWY-01..09 | — | E2E pipeline ordering | e2e | `npm run test:e2e -- gateway.e2e-spec` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/gateway/__tests__/public-paths.spec.ts` — PUBLIC_PATHS / AUTH_ONLY_PATHS allowlist coverage
- [ ] `src/gateway/__tests__/gateway.middleware.spec.ts` — unit tests with mocked services for the 10 stages
- [ ] `src/honeypot/__tests__/honeypot.constants.spec.ts` — HONEYPOT_PATHS literal set
- [ ] `tests/integration/gateway.e2e-spec.ts` — full pipeline e2e covering GTWY-01..09 (real Postgres, mocked ProxyService)
- [ ] `tests/integration/gateway-pipeline-order.e2e-spec.ts` — ordering assertions via stage-name spy on `MetricsService.observeStageDuration`

*Existing infrastructure: jest 30.x, NestJS testing module, real Postgres via docker-compose, `@nestjs/testing` Test.createTestingModule.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Tarpit 2–5s delay timing | GTWY-09 | Time-sensitive sleep introduces flakiness in CI; covered by Phase 2 unit tests | Confirm `Ja4hMiddleware` tarpit unchanged; observe via existing Phase 2 spec |
| Stage histogram visualization | GTWY-08 | Grafana/Prometheus dashboard rendering | Boot stack via `docker-compose up`, send 100 requests, verify `zt_gateway_stage_duration_seconds_bucket{stage="mfa"}` appears in `/metrics` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (5 spec files)
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

## Sign-off rationale

Phase 10 (gateway-integration) is Nyquist-compliant as of 2026-05-12 on the strength of pre-existing automated coverage; this sign-off is a process-only promotion (no new specs authored).

- **VERIFICATION.md score:** 9/9 (`.planning/phases/10-gateway-integration/10-VERIFICATION.md`, status: passed).
- **Milestone audit anchor:** `.planning/v1.0-MILESTONE-AUDIT.md` Phase Status Matrix row 10 records score 9/9 and confirms functional coverage is locked.
- **Deferred HUMAN-UAT carryover (non-blocking, per audit framing "automated must-haves verified"):** none.
- **Pre-flight gate (Phase 17 D-07):** Full unit + e2e suites green and `npm run lint` exit recorded in `.planning/phases/17-v1-0-nyquist-signoff-sweep/17-preflight.txt`.
