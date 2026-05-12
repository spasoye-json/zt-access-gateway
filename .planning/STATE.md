---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: Tech Debt Cleanup
status: executing
stopped_at: Phase 16 context gathered
last_updated: "2026-05-12T19:21:35.149Z"
last_activity: 2026-05-12
progress:
  total_phases: 5
  completed_phases: 3
  total_plans: 17
  completed_plans: 12
  percent: 71
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-11)

**Core value:** Every request is verified, scored, and authorized before reaching any downstream service
**Current focus:** Phase 16 — v1-0-legacy-harness-and-lint-repairs

## Current Position

Phase: 16 (v1-0-legacy-harness-and-lint-repairs) — EXECUTING
Plan: 4 of 8
Status: Ready to execute
Last activity: 2026-05-12

Progress: [███████░░░] 71%

## Performance Metrics

**Velocity:**

- Total plans completed: 38 (Phases 1–5)
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 3 | - | - |
| 2 | 2 | - | - |
| 3 | 3 | - | - |
| 4 | 3 | - | - |
| 5 | 9 | ~26min | ~3min |
| 08 | 5 | - | - |
| 09 | 4 | - | - |
| 12 | 2 | - | - |
| 13 | 3 | - | - |

**Recent Trend:**

- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
| Phase 05 P00 | 3min | 2 tasks | 6 files |
| Phase 05 P07 | 2min | 1 tasks | 4 files |
| Phase 05 P01 | 2min | 1 tasks | 2 files |
| Phase 05 P02 | 3min | 1 tasks | 2 files |
| Phase 05 P04 | 2min | 1 tasks | 2 files |
| Phase 05 P03 | 3min | 1 task tasks | 2 files files |
| Phase 05 P05 | 4min | 1 tasks | 5 files |
| Phase 05 P06 | 1min | 1 tasks | 1 files |
| Phase 05 P08 | 6min | 3 tasks | 4 files |
| Phase 06 P00 | 25min | 4 tasks tasks | 6 files files |
| Phase 06 P01 | 2min | 5 tasks | 8 files |
| Phase 06 P02 | 12min | 2 tasks | 2 files |
| Phase 06 P03 | 5min | 2 tasks | 2 files |
| Phase 06 P04 | 5min | 2 tasks tasks | 4 files files |
| Phase 06 P05 | 3.5min | 2 tasks | 6 files |
| Phase 06 P06 | 12min | 4 tasks | 5 files |
| Phase 10 P01 | 2min | 2 tasks | 2 files |
| Phase 10 P02 | 4min | 2 tasks | 3 files |
| Phase 10 PP03 | 3min | 2 tasks tasks | 2 files files |
| Phase 10 P04 | 7min | 2 tasks tasks | 3 files files |
| Phase 10 P05 | 6min | 3 tasks tasks | 7 files files |
| Phase 10 P06 | 25min | 1 tasks | 3 files |
| Phase 12 P01 | 17min | 2 tasks | 4 files |
| Phase 12 P02 | 5min | 1 tasks | 1 files |
| Phase 13 P01 | 3min | 3 tasks | 7 files |
| Phase 13 P02 | 10min | 3 tasks | 5 files |
| Phase 14 P01 | 35min | 6 tasks | 9 files |
| Phase 14 P03 | 10min | 3 tasks | 5 files |
| Phase 14 P04 | 20min | - tasks | - files |
| Phase 16 P01 | 4min | 2 tasks | 1 files |
| Phase 16 P02 | 8min | 2 tasks tasks | 2 files files |
| Phase 16 P03 | 2min | 1 tasks | 82 files |

## Quick Tasks Completed

| Date | Slug | Summary |
|------|------|---------|
| 2026-04-18 | sync-requirements-post-phase-3 | Synced REQUIREMENTS, ROADMAP, STATE, PROJECT with Phase 3 implementation and planning truth |
| 2026-04-18 | research-roadmap-align | Research docs + PITFALLS phase mapping; deleted `.planning/codebase/`; PROJECT + 04-CONTEXT refs fixed |
| 2026-04-26 | update-progress-docs | Ticked Phase 4/5 + plans 05-02..05-08 in ROADMAP; cleaned malformed JSON in STATE.md; advanced Current focus to Phase 6; flipped commit_docs to false |
| 2026-04-29 | update-stale-planning-docs | Synced PROJECT/REQUIREMENTS/ROADMAP/STATE through Phase 6; promoted decisions, fixed corrupted Phase 7-10 plan lists in ROADMAP, advanced focus to Phase 07 |
| 2026-05-03 | update-docs-post-phase-7-11 | Phase 7 + 11 UAT verified (all tests pass); ROADMAP + STATE advanced to Phase 8 |
| 2026-05-04 | complete-phase-8 | Phase 8 UAT 8/8 passed, security review 29/29 threats closed, docs updated; ROADMAP + STATE advanced to Phase 9 |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- TDD with real Postgres from Phase 4 onward; establish transaction-per-test rollback in first DB-touching module
- Real libs from day one (jose, casbin, opossum, otplib) — no stubs, no mock/prod divergence
- Trust context written ONLY after successful proxy on ALLOW — never on CHALLENGE or DENY
- Audit-before-allow (WAL): ALLOW blocked until audit write succeeds; if exhausted after 3 retries, DENY
- JA4H-04 (per REQUIREMENTS): UserClaims correlation fields shipped in Phase 3; per-user FingerprintStore indexing deferred to Gateway (Phase 10)
- Wave 0 stubs use only Jest globals (describe/it.todo) — zero src/hashcash/* imports prevent TS compile breakage before implementation modules exist
- Min 32-char enforcement on HASHCASH_HMAC_SECRET via Joi (D-05 secret separation)
- Defaults match D-17: TTL=120000, capacity=10000, threshold=0.7, min=18, max=22
- Hashcash util (plan 05-01): difficultyForScore parameterized as (score, min, max) so D-17 test/CI knob is honored without env-branching at call site; generalized formula collapses to D-10 round(18 + (score-0.7)*20) when (min,max)=(18,22); hashSolution locked to UTF-8 string concat (Pitfall 6)
- Plan 05-02: UsedNonceStore — dual-mode constructor (number | AppConfigService) keeps tests trivial while supporting Nest DI; lazy eviction only (no timers) matches FingerprintStore; FIFO via Map.keys().next().value sufficient for 120s replay TTL
- Plan 05-04: HashcashMetrics owns private prom-client Registry per @Injectable instance (Pitfall 3); Counter+Histogram exposed as readonly fields for direct consumer access; registry public so Phase 9 MetricsService can merge
- Plan 05-03: HashcashService returns IssuedChallenge { nonce, difficulty, expiresAt } so guard never recomputes — closes T-5-DIFF-RESPONSE-DRIFT class of bugs
- Plan 05-03: verifySolution returns discriminated VerifyResult union (no throws); guard maps reasons to HTTP responses without exception handling
- Plan 05-05: HashcashGuard wired as APP_GUARD; AppModule import order AuthModule -> TrustScoreModule -> HashcashModule -> HoneypotModule (Pitfall 2 enforced)
- Plan 05-05: Single source of truth for difficulty — guard destructures { nonce, difficulty, expiresAt } from HashcashService.issueChallenge; never recomputes (closes T-5-DIFF-RESPONSE-DRIFT)
- Plan 05-05: D-07 trustScore seam typed via Express.Request augmentation in src/shared/express.d.ts; falls back to TrustScoreService.evaluateScore when undefined
- Plan 05-06: e2e proves env-driven difficulty (DIFFICULTY_MIN=MAX=4) flows through AppConfigService -> HashcashService cfg -> difficultyForScore on issue+verify; closes HCSH-06 verification gap
- Plan 05-08: D-02 identity binding enforced in verifySolution — closes Truth #5 / CR-01 gap from 05-VERIFICATION.md (cross-user / cross-device replay rejected with reason 'identity_mismatch')
- [Phase 06]: Plan 06-00: Exported validationSchema from config.module.ts so per-test bootstrap re-validates against current process.env (ConfigModule.forRoot evaluates schema once per call)
- [Phase 06]: Plan 06-00: helpers.message({ custom: ... }) chosen for Joi.custom() — Joi 18 rejects helpers.error('any.invalid', { message }); .message() is the documented idiom
- [Phase 06]: Plan 06-00: Pitfall 1 canary at src/policy/__tests__/ (jest roots: ['<rootDir>/src'] excludes top-level policy/)
- [Phase 06]: Plan 06-01: extractJa4h reads (req as any)['x-ja4h'] not req.headers — spec includes regression-guard test (B2 wiring)
- [Phase 06]: Plan 06-01: PolicyDecision ALLOW.matchedSubject required (not optional) — encodes invariant ALLOW always corresponds to matched Casbin subject
- [Phase 06]: Plan 06-01: buildSubjects defensive on roles ?? []; normalizeResource preserves case (Pitfall 9)
- [Phase 06]: Plan 06-02: PolicyEvaluatorService never throws on Casbin/policy paths — fail-closed runtime returns DENY policy_error + emits policy.deny + increments metrics.errors
- [Phase 06]: Plan 06-02: Score seam mirrors hashcash.guard.ts (req.trustScore-first, fallback to TrustScoreService.evaluateScore(ctx)) — single contract reused across Phase 5 + 6
- [Phase 06]: Plan 06-02: addRule/removeRule both apply Pitfall 1 hardening (throw if savePolicy() returns false) — operators discover model.conf misconfig at first admin write, not after restart
- [Phase 06-03]: Effective threat level = max across signal types (D-19); manual override matching current auto level skips transitionTo to avoid spurious counter increments
- [Phase 06-03]: ThreatEscalationService uses injectable @Inject(THREAT_CLOCK) ClockFn for deterministic cooldown specs (Pitfall 8 closure) — no jest.useFakeTimers
- [Phase 06-04]: PolicyAdminController is a thin pass-through — class-level @Roles('admin') + DTO-typed @Body delegates to PolicyEvaluatorService (writer mutex inside) and ThreatEscalationService; no controller-level concurrency primitives
- [Phase 06-04]: POST /policy/admin/rules is idempotent — duplicate returns { added: false } at 200, not 409, matching Casbin addPolicy semantics and avoiding rule-existence side channel
- [Phase 06-04]: Structured-only body convention (D-22 Claude's Discretion) — class-validator DTOs even for single-field escalation level; deferred 400/403 e2e cases to Plan 06-06
- [Phase 06-05]: emit AUTH_INVALID_TOKEN at JwtAuthGuard catch site (not AuthService) and HONEYPOT_TRIGGER at ShadowController (not SecurityMetricsService); services stay request-agnostic
- [Phase 06-06]: ShadowController @Public class-level — JwtAuthGuard became global APP_GUARD in Phase 3, breaking honeypot reachability without @Public (Rule 2 fix during e2e wiring)
- [Phase 06-06]: STATE.md blocker resolved — Casbin reload semantics under concurrent requests closed by D-01 + D-02 (file-backed write-through CSV + writer mutex)
- [Phase 06-06]: EventEmitterModule.forRoot() at AppModule root (D-13); per-module forRoot in Auth/Honeypot remains idempotent with v3 global:true default
- [Phase 06-06]: Fail-closed startup spec isolated to its own file with jest.resetModules() (W4) — prevents AppModule cache contamination across tests
- [Phase 10]: Plan 10-01: PUBLIC_PATHS + isAuthOnlyPath as pure module-scope ReadonlySet exports; prefix match uses p.startsWith(prefix + '/') to close T-10-01 over-match
- [Phase 10]: Plan 10-02: HONEYPOT_PATHS as ReadonlySet<string> in src/honeypot/honeypot.constants.ts (D-16); ShadowController.onModuleInit runtime parity guard + CI parity test (regex over @Get decorators) provide two-layer drift detection. Static-import only — Wave 2 GatewayMiddleware avoids HoneypotModule DI cycle (Pitfall 6 via FingerprintStore). Parity-test regex anchored ^\s*@Get\( to ignore inline JSDoc references.
- [Phase 10]: Plan 10-03: STAGE_LABELS extended additively to 9 entries (mfa at index 7); PipelineStage union auto-widens via tuple inference; new mfaPromotions Counter on private registry (Pitfall 2); labelNames fixed to ['result'] with 'allow'|'reject' values to mitigate T-10-08 (cardinality + identity leak)
- [Phase ?]: [Phase 10]: Plan 10-04: GatewayMiddleware 11-dep constructor (9 services + AppConfigService + EventEmitter2); recordWithTimeout helper for D-11 (200ms cap, on timeout incrementAuditFailure + warn-log); AUDIT_SIGNAL emit ONLY on D-10 WAL exhaustion (not D-11 timeouts); per-stage (Date.now()-t0)/1000 inline at every observe callsite for grep-auditable Pitfall 7; GatewayModule omits HoneypotModule (Pitfall 6 — DI cycle via FingerprintStore)
- [Phase ?]: Plan 10-05: GatewayMiddleware wired into AppModule (D-01) — Ja4hMiddleware first, GatewayMiddleware second; GatewayModule placed AFTER AuditModule and BEFORE HoneypotModule (Pitfall 6)
- [Phase ?]: Plan 10-05: JwtAuthGuard + HashcashGuard APP_GUARDs removed (D-02); enforcement migrated to GatewayMiddleware. JwtAuthGuard re-exported from AuthModule for route-level @UseGuards; RolesGuard APP_GUARD preserved (Pitfall 1)
- [Phase ?]: Plan 10-05: AuthController.revoke decorated with @UseGuards(JwtAuthGuard) (D-04); spec uses overrideGuard().useValue({canActivate:()=>true})
- [Phase ?]: Plan 10-05: Pre-Phase-10 hashcash.e2e + policy.e2e skipped with documented justification — per-route-guard model dismantled; plan 10-06 owns the rewritten full-pipeline e2e
- [Phase ?]: [Phase 10]: Plan 10-06: e2e gateway spec uses override-providers for Proxy/Audit/TrustScore/Policy/Mfa; recordTrustContextAfterAllow spy substitutes for the must_haves trust_signals row count (deferred to UAT)
- [Phase ?]: [Phase 10]: Plan 10-06: Auto-fix Rule 1 — GatewayMiddleware uses reqPath derived from req.originalUrl/req.url because NestJS forRoutes('*') leaves req.path === '/'; AuthService wraps decodeProtectedHeader in try/catch so malformed Authorization → 401 not 500
- [Phase 12]: Plan 12-01: /audit/logs added to AUTH_ONLY_EXACT (not PUBLIC_PATHS) — auth+revocation still runs before AuditController; RolesGuard enforces @Roles('admin') (closes I-01, AUDT-05)
- [Phase 12]: Plan 12-01: /policy/admin added to AUTH_ONLY_PREFIXES — covers /policy/admin/rules and /policy/admin/escalation via existing startsWith matcher (closes I-02, PLCY-06, PLCY-11)
- [Phase 12]: Plan 12-01: OPTIONS early-return placed inline in GatewayMiddleware.use() after reqPath IIFE, before PUBLIC_PATHS check — locally auditable, mirrors existing idiom, avoids MiddlewareConsumer.exclude() complexity (closes I-08, F-p)
- [Phase 12]: Plan 12-02: EscalationLevelDto @IsIn(['Normal','Elevated','Critical']) is Title case — e2e sends 'Elevated' not 'elevated'; ThreatLevel type and setManualLevel match Title case convention
- [Phase ?]: [Phase 13]: Plan 13-01: HashcashGuard orphan deleted; regression spec uses grep-allowlist hybrid — single source of truth for what's permitted to mention deleted class (D-03+D-09 fused)
- [Phase ?]: [Phase 13]: Plan 13-02: Sentinel sequencing placed AFTER revocation (line 159), NOT next to req.user (line 147) — prevents revoked token from polluting the sentinel between auth-success and revocation-check (D-04 verbatim)
- [Phase ?]: [Phase 13]: Plan 13-02: GATEWAY_VALIDATED is Symbol identity (unique symbol) — Symbol identity is process-private; client-controlled HTTP headers or string keys cannot spoof (D-04, T-13-02-01 mitigated; spoof-safety unit test as permanent regression guard)
- [Phase ?]: [Phase 13]: Plan 13-02: JwtAuthGuard reads only the Symbol-keyed property, not bare req.user — defence-in-depth against future code paths that set req.user without running auth (D-04, T-13-02-02)
- [Phase ?]: [Phase 14]: Plan 14-01: EventEmitter2 seam for orphan MetricsService seams — MetricsModule transitively imports FingerprintModule (via HoneypotModule) and AuthModule (via PolicyModule); reverse direct injection creates a DI cycle. Matches audit.record_failed precedent (D-01)
- [Phase ?]: [Phase 14]: Plan 14-01: Drift event emitted from Ja4hDriftProvider.compute drift branch (not Ja4hMiddleware as audit phrased) — middleware runs before auth with no prior-fingerprint state; row.ja4h !== ctx.ja4h is the only physically correct emit site (D-02)
- [Phase ?]: [Phase 14]: Plan 14-01: AuthController emits AUTH_TOKEN_REVOKED ONLY after revocationService.revoke success (after 403 ownership check); spec covers both branches so counter never inflates on forbidden attempts
- [Phase ?]: [Phase 14]: Plan 14-01: New src/metrics/metrics-events.ts mirrors policy-events.ts shape — per-direction event-name constants module avoids string-typo drift across emit/subscribe sites (D-03)
- [Phase ?]: [Phase 14]: Plan 14-03: ThreatEscalationService 6th @OnEvent for MFA_RATE_LIMITED + threatElevatedMfaRateLimited/threatCriticalMfaRateLimited (defaults 5/15) — closes v1.0 audit Item 11 (credential-stuffing aggregator gap)
- [Phase ?]: [Phase 14]: Plan 14-03: Joi cross-field validator extended (THREAT_ELEVATED_MFA_RATE_LIMITED < THREAT_CRITICAL_MFA_RATE_LIMITED) — fail-fast on threshold misorder, mirrors honeypot pair
- [Phase ?]: 14-04: Delete-only path — MfaGuard had zero @UseGuards consumers; wiring at /mfa/* would have duplicated GatewayMiddleware step 9b (D-11)
- [Phase ?]: 14-04: Permanent grep regression spec mirrors Phase 13 D-03 hashcash pattern; empty allowlist — MfaGuard never reached production (D-13)
- [Phase ?]: 14-04: Module-comment phrasing avoids the literal token 'MfaGuard' (uses 'orphan guard export removed') so the regression spec's zero-hits invariant holds without losing the audit-trail breadcrumb
- [Phase ?]: [Phase 16]: Plan 16-01: bootstrap.e2e-spec unknown-route assertion adapted from 404 → 401 (post-Phase-10 GatewayMiddleware enforces auth before route resolution); T-01-13 stack-leak guard preserved verbatim; atomic single-file fix(16) commit per D-09/D-11
- [Phase ?]: [Phase 16]: Plan 16-02: Pitfall 4 (no-redeclare on Express Request/Response) DID NOT reproduce under real v8 — shim artefact; drop the rule-disable from all Wave 3 plans
- [Phase ?]: [Phase 16]: Plan 16-02: real-v8 lint surface 1585 err / 136 warn within +12%/+5% of shim (1410/129) — A2 (±20%) holds; D-04 disposition unchanged; Wave 3 sizing uses this measurement
- [Phase ?]: [Phase 16]: Plan 16-02: SECURITY_TOOL_APPROVED=true bypass required for npm install/test — work-project security wrapper leaks into PATH; no project-level config change
- [Phase ?]: [Phase 16]: Plan 16-03: Used prettier --write (Approach B) instead of eslint --fix to keep the style(16) commit a pure single-rule-category atomic per D-12 — eslint --fix would have swept in unrelated autofixes (no-unnecessary-type-assertion etc.)
- [Phase ?]: [Phase 16]: Plan 16-03: Pitfall 3 (line-ending flap) did NOT manifest — endOfLine: 'auto' already in .prettierrc; 394 → 0 prettier hits in 82 *.ts files across src/test/tests

### Roadmap Evolution

- Phase 11 added: Client SDK — auto-solve PoW (429 intercept + retry) and MFA challenge handling

### Pending Todos

None yet.

### Blockers/Concerns

_Resolved 2026-04-26 in Phase 6 Plan 06: Casbin reload semantics under concurrent requests closed by D-01 (file-backed write-through CSV) + D-02 (single shared Enforcer behind async-mutex writer mutex). See 06-06-SUMMARY.md._

_Resolved 2026-05-04: Phase 8 opossum/mTLS wiring — MtlsService.getHttpsAgent() is async; ProxyService awaits it per-request. opossum wraps the full retry loop (not individual attempts) so transient failures don't prematurely trip the breaker. See 08-02-SUMMARY.md._

## Session Continuity

Last session: 2026-05-12T19:21:22.625Z
Stopped at: Phase 16 context gathered

**Planned Phase:** 05 (hashcash-pow) — 9 plans — 2026-04-26T08:20:40.720Z
