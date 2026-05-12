---
phase: 13
validated_at: 2026-05-12
nyquist_compliant: true
requirements_total: 12
covered: 12
partial: 0
missing: 0
manual_only: 0
---

# Phase 13 Validation — v1.0 Tech Debt Cleanup

Phase 13 closes three non-functional tech-debt items flagged by the v1.0 milestone audit (Items 5/6/7): HashcashGuard orphan removal, AUTH_ONLY double-validation closure via a Symbol-keyed sentinel, and audit-metrics content-type assertion brittleness. `13-VERIFICATION.md` (2026-05-11T20:56:51Z, status: passed) records all 12 truths verified. No implementation files modified during this validation pass — this is a read-only Nyquist audit anchor per Phase 17 D-01.

## Test Infrastructure

| Aspect | Value |
|---|---|
| Framework | Jest 30.0.0 + ts-jest 29.2.5 |
| Unit config | `package.json` jest section, `testRegex: .*\.spec\.ts$`, roots `<rootDir>/src` |
| E2E config | `tests/jest-e2e.json` (covers `tests/integration/*.e2e-spec.ts`) |
| Runner | `./node_modules/.bin/jest <path>` (npx disabled) |
| Type check | `nest build` — exit 0 (audit-time) |
| Lint | Pre-existing infra blocker (`typescript-eslint` meta-package missing) — out of Phase 13 scope; not a gate |
| DB specs | Auto-skip if `DATABASE_URL` unset (standard pattern) |

Audit-time totals (transcribed verbatim from `13-VERIFICATION.md` Behavioral Spot-Checks):

- `src/hashcash/__tests__/no-hashcash-guard.regression.spec.ts`: **2/2 passing**
- `src/auth/__tests__/jwt-auth.guard.spec.ts`: **20/20 passing** (includes 3 sentinel cases under `GatewayMiddleware sentinel short-circuit (Phase 13 D-04/D-05)` describe block)
- `tests/integration/admin-routes.e2e-spec.ts`: **14/14 passing** (includes 3 SC-2 `toHaveBeenCalledTimes(1)` cases on `/policy/admin/rules` and `/auth/revoke`)
- `tests/integration/audit-metrics.e2e-spec.ts`: **6/6 passing**
- `nest build`: **exit 0** (no TypeScript compile errors)

## Per-SC Map

### SC-1 — HashcashGuard orphan removed + permanent regression spec

Anchored to `13-VERIFICATION.md` truth rows 1–5: SC-1 closure (row 1), D-01 full-deletion (row 2), D-02 module comment cleanup (row 3), D-03 permanent regression spec (row 4), and D-09 dangling JSDoc rewrites (row 5). Implementation commit: `730b651` (full deletion of `src/hashcash/hashcash.guard.ts` + `src/hashcash/__tests__/hashcash.guard.spec.ts`).

| Behaviour | Test |
|---|---|
| `src/hashcash/hashcash.guard.ts` absent on disk | filesystem assertion in `no-hashcash-guard.regression.spec.ts` |
| Grep across `src/` + `tests/` returns zero `HashcashGuard` references outside the documented allowlist (`app.module.ts`, `hashcash.e2e.spec.ts`, `policy.e2e.spec.ts`) | `execSync` + `\bHashcashGuard\b` regex in `no-hashcash-guard.regression.spec.ts` (D-09 allowlist embedded) |
| `hashcash.module.ts` no longer mentions `HashcashGuard` in any form (D-02) | grep assertion: `grep -c HashcashGuard src/hashcash/hashcash.module.ts` = 0 |
| Dangling JSDoc references rewritten in `mfa.service.ts`, `shared/express.d.ts`, `shared/http-exception.filter.ts` (D-09 REWRITE sites = 0 hits each) | indirect: regression spec passes only when allowlist is exhaustive |

**Status: covered.**

**Commands:**
- `./node_modules/.bin/jest src/hashcash/__tests__/no-hashcash-guard.regression.spec.ts`

### SC-2 — JwtAuthGuard sentinel short-circuit (single `validateToken` call per AUTH_ONLY request)

Anchored to `13-VERIFICATION.md` truth rows 6–11: SC-2 short-circuit behaviour (row 6), D-04 Symbol non-spoofability (row 7), D-04 sequencing AFTER auth + revocation (row 8), D-05 canActivate order (row 9), D-06 revocation re-check intentionally skipped on sentinel (row 10), D-07 standalone-route full-validation preservation (row 11). Implementation files: `src/gateway/gateway-validated.symbol.ts` (Symbol export), `src/gateway/gateway.middleware.ts:159` (sentinel assignment between revocation observe and AUTH_ONLY early-exit), `src/auth/jwt-auth.guard.ts:56-58` (sentinel branch between `isPublic` and `validateToken`).

| Behaviour | Test |
|---|---|
| Sentinel-present → guard returns true WITHOUT calling `validateToken` / `isRevoked` / emitting | `src/auth/__tests__/jwt-auth.guard.spec.ts` (D-06 case) |
| Sentinel-absent → guard calls `validateToken` exactly once (strict `=== true` check) | `src/auth/__tests__/jwt-auth.guard.spec.ts` (D-07 case) |
| String-valued sentinel header does NOT bypass (Symbol identity unique to process) | `src/auth/__tests__/jwt-auth.guard.spec.ts` spoof-safety case |
| Live pipeline: `POST /policy/admin/rules` and `POST /auth/revoke` each call `validateToken` exactly once across middleware + guard | `tests/integration/admin-routes.e2e-spec.ts` two `toHaveBeenCalledTimes(1)` assertions |

**Status: covered.**

**Commands:**
- `./node_modules/.bin/jest src/auth/__tests__/jwt-auth.guard.spec.ts`
- `./node_modules/.bin/jest --config tests/jest-e2e.json tests/integration/admin-routes.e2e-spec.ts`

### SC-3 — audit-metrics content-type assertion order-agnostic

Anchored to `13-VERIFICATION.md` truth row 12. Implementation site: `tests/integration/audit-metrics.e2e-spec.ts:76-78` — a single-line regex was replaced with three independent clauses (`toContain('text/plain')` + `toMatch(/version=0\.0\.4/)` + `toMatch(/charset=utf-8/)`) so the assertion no longer breaks when prom-client reorders its `Content-Type` parameters.

| Behaviour | Test |
|---|---|
| `/metrics` response content-type contains `text/plain` regardless of parameter order | `audit-metrics.e2e-spec.ts:76-78` clause 1 |
| `/metrics` response content-type contains `version=0.0.4` regardless of parameter order | `audit-metrics.e2e-spec.ts:76-78` clause 2 |
| `/metrics` response content-type contains `charset=utf-8` regardless of parameter order | `audit-metrics.e2e-spec.ts:76-78` clause 3 |

**Status: covered.**

**Command:** `./node_modules/.bin/jest --config tests/jest-e2e.json tests/integration/audit-metrics.e2e-spec.ts`

### SC-4 — Phase-wide regression (green suite + `nest build`)

Anchored to `13-VERIFICATION.md` Behavioral Spot-Checks last row (`nest build` exit 0) and Anti-Patterns Found table (none in 13-scoped files). Plan-trail commits: `ede9631` / `730b651` / `d6e09dc` (13-01); `7a4487d` / `5a71502` / `1b4ccf6` (13-02); `9dc6ad8` (13-03).

| Behaviour | Test |
|---|---|
| TypeScript compile clean across all phase-13 touched files | `nest build` → exit 0 |
| Targeted unit + e2e specs above remain green (no regressions in adjacent files) | `jest` invocations per SC-1..SC-3 commands |

The pre-existing `npm run lint` blocker (missing `typescript-eslint` meta-package, ESLint flat-config v8 idiom) and the pre-existing full-unit-suite `--forceExit` requirement (ProxyService circuit-breaker timer leaks) are documented in `13-01-SUMMARY` and `13-VERIFICATION.md` "Pre-existing infra issues" — both pre-dated Phase 13 and are explicitly OUT of Phase 13 scope per CLAUDE.md scope boundary. They do not constitute Phase 13 Nyquist gaps. Phase 16 subsequently closed the lint blocker (post-Phase-13).

**Status: covered.**

## Closure Anchors for Audit Items 5, 6, 7

Phase 13 was scoped specifically to close three items from a prior v1.0 milestone audit. The evidentiary anchors for those closures are:

- **Item 5 (HashcashGuard orphan, dead-export bloat)** → `.planning/phases/13-v1-0-tech-debt-cleanup/13-REVIEW.md` and `13-REVIEW-FIX.md` document the deletion path; `.planning/v1.0-MILESTONE-AUDIT.md` Phase Status Matrix row 13 cites 12/12 and the prior audit's `carryover_findings_closed` block names Item 5. SC-1 above wires the closure to a permanent regression spec.
- **Item 6 (AUTH_ONLY double-validation — JwtAuthGuard re-runs validateToken after GatewayMiddleware already passed)** → same REVIEW / REVIEW-FIX files document the Symbol-keyed sentinel design (D-04). SC-2 above wires the closure to both unit-level spoof-safety tests and live e2e `toHaveBeenCalledTimes(1)` assertions on real admin routes.
- **Item 7 (audit-metrics content-type brittleness)** → same REVIEW / REVIEW-FIX files document the three-clause split-and-assert pattern. SC-3 above wires the closure to a single mechanical assertion that survives prom-client parameter-order reshuffling.

`.planning/v1.0-MILESTONE-AUDIT.md` carries Phase 13 with score `passed 12/12` (`Closed Items 5, 6, 7 from earlier audit`) and the prior audit's `prior_audit_resolution.carryover_findings_closed` list named these exact items.

## Manual-Only Items

None. All 12 truths in `13-VERIFICATION.md` are mechanically verifiable (file existence, grep counts, jest runs); `13-VERIFICATION.md` "Human Verification Required" section states: "None. All three success criteria are mechanically verifiable. No UX, no visual, no external-service integration."

## Sign-Off

- nyquist_compliant: **true**
- Phase 13 closes with full automated coverage of all 12 success-criteria-derived truths from `13-VERIFICATION.md`.
- No implementation files modified during this validation pass (read-only audit per Phase 17 D-01).
- Result: **GAPS FILLED.**
