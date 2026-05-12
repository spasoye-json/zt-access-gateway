---
phase: 8
slug: proxy-bopla
status: finalized
nyquist_compliant: true
validated_at: 2026-05-12
wave_0_complete: false
created: 2026-05-04
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | jest 30.x |
| **Config file** | `package.json` (jest section) |
| **Quick run command** | `npx jest src/proxy/ --testPathPattern="proxy\|bopla\|service-registry\|dns-rebinding\|response-validator" --passWithNoTests` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx jest src/proxy/ --testPathPattern="proxy\|bopla\|service-registry\|dns-rebinding\|response-validator" --passWithNoTests`
- **After every plan wave:** Run `npm test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 08-00-01 | 00 | 0 | PRXY-04 | — | opossum installed and importable | unit | `node -e "require('opossum')"` | ❌ W0 | ⬜ pending |
| 08-01-01 | 01 | 1 | PRXY-03/PRXY-06 | T-08-SSRF | ServiceRegistryService rejects unknown service | unit | `npx jest src/proxy/__tests__/service-registry.service.spec.ts` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 1 | PRXY-07/PRXY-08 | T-08-SSRF | DnsRebindingGuard blocks loopback + metadata IPs | unit | `npx jest src/proxy/__tests__/dns-rebinding.guard.spec.ts` | ❌ W0 | ⬜ pending |
| 08-01-03 | 01 | 1 | PRXY-09 | — | ResponseValidator status + Content-Type guard | unit | `npx jest src/proxy/__tests__/response-validator.spec.ts` | ❌ W0 | ⬜ pending |
| 08-02-01 | 02 | 2 | PRXY-01/PRXY-02/PRXY-04/PRXY-05 | T-08-mTLS | ProxyService forward: mTLS, headers, retry, opossum | unit | `npx jest src/proxy/__tests__/proxy.service.spec.ts` | ❌ W0 | ⬜ pending |
| 08-03-01 | 03 | 3 | BOPL-01..BOPL-04 | — | BoPlaInterceptor: field-policy.json + role-based stripping | unit | `npx jest src/proxy/__tests__/bopla.interceptor.spec.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

The five spec files below are the RED test scaffolds Plan 08-00 creates (one per Phase 8 source unit). All start as `it.todo` stubs and turn GREEN as later plans implement against them.

- [ ] `src/proxy/__tests__/service-registry.service.spec.ts` — stubs for PRXY-03, PRXY-06 (filled by plan 08-01)
- [ ] `src/proxy/__tests__/dns-rebinding.guard.spec.ts` — stubs for PRXY-07, PRXY-08 (filled by plan 08-01)
- [ ] `src/proxy/__tests__/response-validator.spec.ts` — stubs for PRXY-09 (filled by plan 08-01)
- [ ] `src/proxy/__tests__/proxy.service.spec.ts` — stubs for PRXY-01, PRXY-02, PRXY-04, PRXY-05 (filled by plan 08-02)
- [ ] `src/proxy/__tests__/bopla.interceptor.spec.ts` — stubs for BOPL-01..BOPL-04 (filled by plan 08-03)
- [ ] `policy/field-policy.json` — starter policy file (no test file, but needed by BOPL-02)
- [ ] `npm install opossum && npm install --save-dev @types/opossum @types/micromatch`
- [ ] If ts-jest reports `CircuitBreaker is not a constructor`, add `opossum` to `transformIgnorePatterns` in `package.json`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Actual mTLS handshake to downstream | PRXY-01 | Requires real certs + live server | `docker-compose up` then `curl --cert ... https://localhost:3000/...` |
| Circuit breaker half-open probe | PRXY-04 | Requires timing-sensitive state machine | Send N failures, wait for open, verify half-open probe succeeds |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

## Sign-off rationale

Phase 08 (proxy-bopla) is Nyquist-compliant as of 2026-05-12 on the strength of pre-existing automated coverage; this sign-off is a process-only promotion (no new specs authored).

- **VERIFICATION.md score:** 13/13 (`.planning/phases/08-proxy-bopla/08-VERIFICATION.md`, status: passed — re-verification closed 3 gaps from prior 10/13 audit).
- **Milestone audit anchor:** `.planning/v1.0-MILESTONE-AUDIT.md` Phase Status Matrix row 08 records score 13/13 and confirms functional coverage is locked.
- **Deferred HUMAN-UAT carryover (non-blocking, per audit framing "automated must-haves verified"):** none.
- **Pre-flight gate (Phase 17 D-07):** Full unit + e2e suites green and `npm run lint` exit recorded in `.planning/phases/17-v1-0-nyquist-signoff-sweep/17-preflight.txt`.
