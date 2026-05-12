# Zero-Trust Access Gateway

## What This Is

A hardened NestJS zero-trust access gateway with a 10-step fail-fast pipeline. Every inbound request passes through JA4H fingerprinting, honeypot detection, authentication, token revocation check, 7-signal trust scoring, hashcash PoW (for high-risk requests), Casbin policy evaluation, MFA challenge, mTLS proxy forwarding, and BOPLA response field stripping — with audit WAL and security-specific Prometheus metrics. Being rebuilt from scratch using TDD.

## Core Value

Every request is verified, scored, and authorized before reaching any downstream service — no implicit trust, no shortcuts.

## Requirements

### Validated

- [x] Phase 1 — Config module, shared infra (mTLS loader, health, bootstrap stack) — see `.planning/ROADMAP.md`
- [x] Phase 2 — JA4H fingerprinting, `FingerprintStore` blacklist, shadow honeypot decoys + metrics
- [x] Phase 3 — JWT auth (jose), `JwtAuthGuard`, `RolesGuard`, JTI revocation, POST `/auth/revoke` — see `src/auth/`
- [x] Phase 4 — 7-signal trust score, Postgres persistence, record-after-ALLOW pattern
- [x] Phase 5 — Hashcash PoW guard, HMAC challenges, identity-bound verification, env-driven difficulty
- [x] Phase 6 — Casbin RBAC policy evaluation, fail-closed DENY, ThreatEscalationService with auto-cooldown, policy admin REST API
- [x] Phase 7 — MFA challenge lifecycle with fingerprint-bound MFA JWT and rate limiting
- [x] Phase 8 — mTLS proxy with circuit breaker, retries, SSRF protection, BOPLA response stripping
- [x] Phase 9 — Audit logging (audit-before-allow) + Prometheus security metrics
- [x] Phase 10 — 10-step fail-fast GatewayMiddleware orchestrating the full hardened pipeline
- [x] Phase 11 — Developer experience: auto-solve PoW in gateway pipeline + MFA dev mode
- [x] Phase 12 — Admin route allowlist closure
- [x] Phase 13 — v1.0 tech-debt cleanup
- [x] Phase 14 — v1.0 milestone validation
- [x] Phase 15 — eslint flat-config migration
- [x] Phase 16 — Strict typescript-eslint pass (no-floating-promises, --max-warnings 0)
- [x] Phase 17 — v1.0 Nyquist sign-off sweep (milestone closes with overall: compliant)

### Active

- [ ] Docker Compose stack for full observability stack (Prometheus + Grafana + sample microservices — v1 compose is gateway + Postgres only)

### Out of Scope

- Frontend/UI — this is a backend gateway only
- Custom auth provider integration (OAuth, SAML) — JWT-only for now
- Horizontal scaling / clustering — single-instance design
- Admin dashboard — policy managed via REST API and CSV files

## Context

- Architecture and phase order: `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, `docs/HARDENING_ARCHITECTURE.md`, `.planning/research/` (background only — must match roadmap)
- `src/` is the **greenfield** implementation built phase-by-phase (Phases 1–3 shipped; no separate “legacy” tree to consult)
- Key libraries: jose (JWT), casbin (RBAC), @nestjs/axios (proxy), prom-client (metrics), opossum (circuit breaker), otplib (TOTP), raw pg (no ORM)
- Hardening architecture documented in docs/HARDENING_ARCHITECTURE.md with Mermaid diagrams
- Pipeline flow diagrams in docs/DIAGRAMS.md
- Postgres required for trust_signals, trust_activity, audit_logs, mfa_challenges, mfa_tokens tables
- mTLS certificates for downstream service communication

## Constraints

- **Tech stack**: NestJS + TypeScript — non-negotiable, existing scaffold in place
- **Testing**: TDD — write test first, then implementation. Real Postgres via Docker for DB tests. Real libraries (jose, casbin, https) from day one.
- **Build order**: Layer-by-layer following pipeline dependency chain. Each module fully tested before moving to the next.
- **Database**: PostgreSQL for all persistent state
- **Observability**: Prometheus-compatible metrics

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| TDD with real Postgres | Catch real DB issues early, no mock/prod divergence | In progress — DB tests from Phase 4 |
| Real libs from start (no stubs) | Avoid stub-to-real migration pain, tests reflect real behavior | **Applied** Phases 1–3 (jose, pg in deps for later) |
| Layer-by-layer build order | Follows natural dependency chain, each layer testable in isolation | **Applied** through Phase 3 |
| Full pipeline in v1 | All 7 modules + orchestrator, no partial gateway | Pending — through Phase 10 |
| Full hardened architecture in v1 | JA4H, honeypots, hashcash, BOPLA, threat escalation, audit WAL — no base-then-harden split | In progress |
| Audit-before-allow (WAL) | ALLOW decisions blocked until audit write succeeds; if audit fails, DENY | Pending — Phase 9 |
| TDD with real Postgres + transaction-per-test | Catch real DB issues; trust signals must round-trip | **Applied** Phase 4 onward |
| Trust context written ONLY after successful proxy on ALLOW | Prevents CHALLENGE bypass attack on telemetry | **Applied** Phase 4 (TRST-09) |
| Hashcash difficulty scales 18→22 bits over score 0.7→0.9 | Tunable risk-adaptive PoW (D-10) | **Applied** Phase 5 |
| HashcashGuard wired as APP_GUARD; identity binding in verifySolution | Closes cross-user/cross-device replay (D-02) | **Applied** Phase 5 plan 08 |
| Casbin enforcer fail-closed: errors return DENY policy_error | No accidental ALLOW on policy bugs | **Applied** Phase 6 (PLCY-05) |
| Casbin write-through CSV + async-mutex writer mutex | Concurrent admin writes preserve ordering, survive restart | **Applied** Phase 6 plan 02 |
| ThreatEscalationService level = max across signal types; cooldown via injected ClockFn | Deterministic specs without fake timers; D-19 | **Applied** Phase 6 plan 03 |
| EventEmitterModule.forRoot() at AppModule root only | Single global emitter; per-module forRoot deduplicates (D-13) | **Applied** Phase 6 plan 06 |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? -> Move to Out of Scope with reason
2. Requirements validated? -> Move to Validated with phase reference
3. New requirements emerged? -> Add to Active
4. Decisions to log? -> Add to Key Decisions
5. "What This Is" still accurate? -> Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-12 — v1.0 milestone complete (Phases 1–17). Nyquist coverage: 14 compliant / 0 partial / 0 missing; overall: compliant.*
