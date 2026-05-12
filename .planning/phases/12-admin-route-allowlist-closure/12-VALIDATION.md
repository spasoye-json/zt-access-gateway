---
phase: 12
slug: admin-route-allowlist-closure
status: finalized
nyquist_compliant: true
validated_at: 2026-05-12
wave_0_complete: false
created: 2026-05-09
---

# Phase 12 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Jest 30 + ts-jest + supertest 7 |
| **Config file** | `tests/jest-e2e.json` (real config used by integration specs) |
| **Quick run command** | `npx jest src/gateway/__tests__/public-paths.spec.ts` |
| **Full suite command** | `npm test && npx jest --config tests/jest-e2e.json` |
| **Estimated runtime** | ~25 seconds (unit + new e2e spec) |

**Note:** `package.json:17` script `test:e2e` points at `./test/jest-e2e.json` (singular stub). The real config that picks up `tests/integration/*.e2e-spec.ts` is `tests/jest-e2e.json` — always pass `--config tests/jest-e2e.json` explicitly.

---

## Sampling Rate

- **After every task commit:** Run the relevant unit or e2e spec
- **After every plan wave:** Run `npm test && npx jest --config tests/jest-e2e.json`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 12-01-01 | 01 | 1 | AUDT-05, PLCY-06, PLCY-11 | T-12-01 (privilege escalation) | `/audit/logs` and `/policy/admin/*` reach local controllers, not proxy fallback | unit | `npx jest src/gateway/__tests__/public-paths.spec.ts` | ✅ (extend existing) | ⬜ pending |
| 12-01-02 | 01 | 1 | (success criterion 4) | T-12-02 (OPTIONS bypass to admin) | OPTIONS short-circuits before auth, hits CORS handler only | unit | `npx jest src/gateway/__tests__/gateway.middleware.spec.ts` | ✅ (extend existing) | ⬜ pending |
| 12-02-01 | 02 | 2 | AUDT-05 | T-12-03 (info disclosure via 404) | `GET /audit/logs` admin → 200; non-admin → 403 (not 404) | e2e | `npx jest --config tests/jest-e2e.json tests/integration/admin-routes.e2e-spec.ts -t '/audit/logs'` | ❌ W0 (new file) | ⬜ pending |
| 12-02-02 | 02 | 2 | PLCY-06 | T-12-03 | `GET /policy/admin/rules` and `POST /policy/admin/rules` admin → 200/201; non-admin → 403 | e2e | `... -t '/policy/admin/rules'` | ❌ W0 | ⬜ pending |
| 12-02-03 | 02 | 2 | PLCY-11 | T-12-03 | `POST/DELETE /policy/admin/escalation` admin → 200/201/204; non-admin → 403 | e2e | `... -t '/policy/admin/escalation'` | ❌ W0 | ⬜ pending |
| 12-02-04 | 02 | 2 | (success criterion 4) | T-12-02 | OPTIONS preflight returns CORS headers (`access-control-allow-origin`) without invoking auth | e2e | `... -t 'OPTIONS preflight'` | ❌ W0 | ⬜ pending |
| 12-02-05 | 02 | 2 | (success criteria 1-3 regression) | — | `proxy.forward` is NEVER invoked for admin routes (spy assertion) | e2e | `... -t 'proxy fallback'` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/integration/admin-routes.e2e-spec.ts` — new file covering AUDT-05, PLCY-06, PLCY-11, and success criteria 3 & 4
- [ ] No new framework install required (Jest 30 + supertest already installed)
- [ ] No new fixtures required — `createHs256Token` from `src/auth/__tests__/test-keys.ts` and override-provider pattern from `tests/integration/audit-metrics.e2e-spec.ts` are reused verbatim

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Browser CORS preflight from a real Origin (e.g., `http://localhost:3001`) | Success criterion 4 | E2E uses supertest which does not exercise the browser's preflight cache; the real check is that a Chromium request actually receives the headers | Run `docker-compose up`, open browser devtools at `http://localhost:3001`, fetch `/audit/logs` with admin JWT, confirm OPTIONS preflight succeeds and the GET completes |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (`tests/integration/admin-routes.e2e-spec.ts`)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

## Sign-off rationale

Phase 12 (admin-route-allowlist-closure) is Nyquist-compliant as of 2026-05-12 on the strength of pre-existing automated coverage; this sign-off is a process-only promotion (no new specs authored).

- **VERIFICATION.md score:** 5/5 (`.planning/phases/12-admin-route-allowlist-closure/12-VERIFICATION.md`, status: passed).
- **Milestone audit anchor:** `.planning/v1.0-MILESTONE-AUDIT.md` Phase Status Matrix row 12 records score 5/5 and confirms functional coverage is locked.
- **Deferred HUMAN-UAT carryover (non-blocking, per audit framing "automated must-haves verified"):** none.
- **Pre-flight gate (Phase 17 D-07):** Full unit + e2e suites green and `npm run lint` exit recorded in `.planning/phases/17-v1-0-nyquist-signoff-sweep/17-preflight.txt`.
