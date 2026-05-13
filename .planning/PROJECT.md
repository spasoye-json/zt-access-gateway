# Zero-Trust Access Gateway

## What This Is

A hardened NestJS zero-trust access gateway with a 10-step fail-fast pipeline. Every inbound request passes through JA4H fingerprinting, honeypot detection, authentication, token-revocation check, 7-signal trust scoring, hashcash PoW (for high-risk requests), Casbin policy evaluation, MFA challenge promotion, mTLS proxy forwarding, and BOPLA response field stripping — backed by audit-before-allow WAL and security-specific Prometheus metrics. v1.0 shipped on 2026-05-13 with all 120 v1 REQ-IDs functionally satisfied and Nyquist sign-off compliant 17/17.

## Current State

**Shipped:** v1.0 — 2026-05-13.
**Phases:** 18 (1–18, including Phase 11 MFA Enrollment).
**Plans:** 75 across the milestone.
**Codebase:** 16,452 LOC `src/` + 2,117 LOC tests/ = 18,569 TypeScript LOC.
**Quality gates:** `npm test` (653 passed), `npm run test:e2e` (5 passed), `npm run lint --max-warnings 0` (exit 0).
**Open debt:** 3 HUMAN-UAT carryover items on Phases 02/07/11 — see `.planning/STATE.md` Deferred Items.

## Core Value

Every request is verified, scored, and authorized before reaching any downstream service — no implicit trust, no shortcuts.

## Requirements

### Validated (v1.0 shipped)

- ✓ JA4H fingerprinting + FingerprintStore blacklist + tarpit-then-403 — v1.0 (Phase 2)
- ✓ Shadow honeypot decoys with terminal trust-score promotion — v1.0 (Phase 2)
- ✓ JWT auth HS256/RS256/ES256 + JWKS + `@Public()` bypass — v1.0 (Phase 3)
- ✓ JTI revocation with ownership-checked `POST /auth/revoke` — v1.0 (Phase 3)
- ✓ 7-signal trust score with record-after-ALLOW Postgres persistence — v1.0 (Phase 4)
- ✓ Hashcash PoW guard with 18→22-bit difficulty scaling + identity binding — v1.0 (Phase 5)
- ✓ Casbin RBAC + auto-tightening threat escalation + cooldown — v1.0 (Phase 6)
- ✓ MFA challenge lifecycle with fingerprint-bound MFA JWT + rate limiting — v1.0 (Phase 7)
- ✓ mTLS proxy with opossum circuit breaker, retries, SSRF + DNS-rebinding protection — v1.0 (Phase 8)
- ✓ BOPLA role-based response field stripping — v1.0 (Phase 8)
- ✓ Audit-before-allow WAL + Prometheus security metrics — v1.0 (Phase 9)
- ✓ 10-step fail-fast `GatewayMiddleware` orchestrator — v1.0 (Phase 10)
- ✓ MFA enrollment (TOTP, AES-256-GCM secrets, admin-gated reset) — v1.0 (Phase 11)
- ✓ Admin route allowlist + OPTIONS preflight bypass — v1.0 (Phase 12)
- ✓ v1.0 tech-debt closure (orphan-guard removal, Symbol-keyed sentinel, content-type test fix) — v1.0 (Phase 13)
- ✓ Observability seam wiring + dead-code purge — v1.0 (Phase 14)
- ✓ Docs & traceability reconciliation (52 stale Pending→Complete; 03-VERIFICATION.md backfill) — v1.0 (Phase 15)
- ✓ ESLint 9 + typescript-eslint v8 with `--max-warnings 0` gate — v1.0 (Phase 16)
- ✓ Nyquist sign-off 17/17 compliant — v1.0 (Phases 17–18)

Full archive: `.planning/milestones/v1.0-REQUIREMENTS.md`.

### Active (next milestone — TBD)

- [ ] Address HUMAN-UAT carryover from v1.0 (Phases 02/07/11 live runtime confirmation)
- [ ] Docker Compose full observability stack (Prometheus + Grafana + sample microservices — v1 compose ships gateway + Postgres only)

### Out of Scope

| Feature | Reason |
|---------|--------|
| Frontend/admin UI | Doubles attack surface; policy-as-code in CSV is git-auditable |
| OAuth2/SAML IdP integration | Gateway validates JWTs from any issuer; IdP integration is a separate product |
| Stateful sessions | Breaks horizontal scalability; requires Redis; JWTs are stateless by design |
| WebSocket proxying | Orthogonal to per-request ZT policy; complex lifecycle management |
| ML-based anomaly detection | 5% of value for 20x complexity; heuristic scoring covers the risk surface |
| Built-in IdP (user/password management) | Different domain; delegate to external IdP |
| DLP / payload inspection | Latency + legal risk (PII in logs); out of scope for metadata-layer gateway |
| Horizontal scaling / clustering | Single-instance design for v1; revisit in v2 with Redis-backed state |

## Context

- v1.0 shipped 2026-05-13 with 18,569 TypeScript LOC across 153 `src/` files.
- Tech stack: NestJS 11, TypeScript 5.7, Node 18+, jose, casbin, otplib, opossum, prom-client, raw `pg`. ESLint 9 + typescript-eslint v8 with `--max-warnings 0`.
- Postgres required for `trust_signals`, `trust_activity`, `audit_logs`, `mfa_challenges`, `mfa_tokens`, `user_secrets`.
- mTLS certs for downstream service communication; CA cert + client cert/key required.
- Pipeline order: JA4H → blacklist → rate limit → honeypot → auth → revocation → trust → hashcash → policy → proxy → BOPLA. Bypass set: `/health`, `/metrics`; AUTH-only set: `/auth/revoke`, `/mfa/*`, `/audit/logs`, `/policy/admin/*`.
- Architecture: `docs/HARDENING_ARCHITECTURE.md`, `docs/DIAGRAMS.md`.
- Roadmap evolved across milestone: Phase 11 (MFA Enrollment) added mid-stream; Phases 12–18 added during audit closure to drive milestone to compliant.
- Known tech debt at close: 3 HUMAN-UAT items (Phases 02/07/11) — see `.planning/STATE.md` Deferred Items.

## Constraints

- **Tech stack**: NestJS + TypeScript — non-negotiable.
- **Testing**: TDD — write test first, then implementation. Real Postgres via Docker for DB tests. Real libraries (jose, casbin, opossum, otplib, pg) from day one — no mocks for production code paths.
- **Build order**: Layer-by-layer following pipeline dependency chain. Each module fully tested before moving to the next.
- **Database**: PostgreSQL for all persistent state. Raw `pg` (no ORM).
- **Observability**: Prometheus-compatible metrics; audit trail to Postgres.
- **Quality gates**: `npm run lint --max-warnings 0`, full unit + e2e suites green, every commit atomic.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| TDD with real Postgres + transaction-per-test | Catch real DB issues; no mock/prod divergence | ✓ Good — applied Phase 4 onward |
| Real libs from start (no stubs) | Avoid stub-to-real migration pain | ✓ Good — jose/casbin/opossum/otplib shipped with implementing phase |
| Layer-by-layer pipeline build order | Each layer testable in isolation | ✓ Good — held through all 18 phases |
| Full hardened architecture in v1 | JA4H, honeypots, hashcash, BOPLA, threat escalation, WAL — no base-then-harden split | ✓ Good — shipped intact |
| Audit-before-allow (WAL) | ALLOW gated on audit-write success; if exhausted, DENY | ✓ Good — Phase 9 |
| Trust context written ONLY after successful proxy on ALLOW | Prevents CHALLENGE-bypass telemetry attack | ✓ Good — Phase 4 (TRST-09) |
| Hashcash difficulty scales 18→22 bits over score 0.7→0.9 | Risk-adaptive PoW; tunable via env | ✓ Good — Phase 5 |
| Hashcash identity binding in `verifySolution` | Closes cross-user/cross-device replay (D-02) | ✓ Good — Phase 5 plan 08 |
| Casbin fail-closed (errors → DENY policy_error) | No accidental ALLOW on policy bugs | ✓ Good — Phase 6 (PLCY-05) |
| Casbin write-through CSV + async-mutex writer | Concurrent admin writes preserve ordering, survive restart | ✓ Good — Phase 6 plan 02 |
| `ThreatEscalation` level = max across signal types; cooldown via injected ClockFn | Deterministic specs without fake timers (D-19) | ✓ Good — Phase 6 plan 03 |
| `EventEmitterModule.forRoot()` at AppModule root only | Single global emitter; per-module forRoot deduplicates (D-13) | ✓ Good — Phase 6 plan 06 |
| MFA JWT bound to userId\|deviceId\|ip (no geo/UA) | Tighter binding without false rejects (D-07) | ✓ Good — Phase 7 |
| `opossum` wraps full retry loop (not per-attempt) | Transient failures don't prematurely trip breaker | ✓ Good — Phase 8 plan 02 |
| Symbol-keyed `GATEWAY_VALIDATED` sentinel | Spoof-safe short-circuit of `JwtAuthGuard` double-validation | ✓ Good — Phase 13 |
| EventEmitter2 fan-in for orphan MetricsService seams | Avoids DI cycle through `MetricsModule` ↔ `FingerprintModule`/`AuthModule` | ✓ Good — Phase 14 |
| `--max-warnings 0` + `no-floating-promises` promoted to error | Lock in lint discipline; no warning drift | ✓ Good — Phase 16 |
| Atomic per-rule-category style commits | Reviewable rollbacks; bisectable history (D-12) | ✓ Good — Phase 16 |
| `.planning/` gitignored; tracked files force-added per case | Keeps execution noise out of git but preserves audit anchors | ✓ Held — Phase 18 used `--allow-empty` for gitignored disk-writes |

## Evolution

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-13 after v1.0 milestone (Phases 1–18 shipped; Nyquist 17/17 compliant; 3 HUMAN-UAT items deferred).*
