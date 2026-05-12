---
phase: 07
slug: mfa-challenge
status: finalized
nyquist_compliant: true
validated_at: 2026-05-12
wave_0_complete: false
created: 2026-05-01
---

# Phase 07 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Jest 30.x |
| **Config file** | `package.json` (jest section) |
| **Quick run command** | `npx jest src/mfa/ --testPathPattern="spec" --passWithNoTests` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~30 seconds (unit) / ~60 seconds (with integration) |

---

## Sampling Rate

- **After every task commit:** Run `npx jest src/mfa/ --testPathPattern="spec" --passWithNoTests`
- **After every plan wave:** Run `npm test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 07-00-01 | 00 | 0 | MFA-01 | — | Config rejects missing/short MFA_JWT_SECRET | unit | `npx jest src/config/ --passWithNoTests` | ❌ W0 | ⬜ pending |
| 07-00-02 | 00 | 0 | MFA-01 | — | Migration creates mfa_challenges, mfa_tokens, user_secrets | integration | `npx jest tests/integration/ --passWithNoTests` | ❌ W0 | ⬜ pending |
| 07-01-01 | 01 | 1 | MFA-01,MFA-06 | — | createChallenge inserts row, returns challengeId+expiresAt | unit | `npx jest src/mfa/__tests__/mfa.service.spec.ts` | ❌ W0 | ⬜ pending |
| 07-01-02 | 01 | 1 | MFA-08 | — | createChallenge rejects with 429 after rate limit exceeded | unit | `npx jest src/mfa/__tests__/mfa.service.spec.ts` | ❌ W0 | ⬜ pending |
| 07-02-01 | 02 | 1 | MFA-02,MFA-03 | T-07-01 | verifyTotp mints MFA JWT with typ:'mfa' signed with MFA_JWT_SECRET | unit | `npx jest src/mfa/__tests__/mfa.service.spec.ts` | ❌ W0 | ⬜ pending |
| 07-02-02 | 02 | 1 | MFA-04 | T-07-02 | validateMfaToken rejects fingerprint mismatch with 401 | unit | `npx jest src/mfa/__tests__/mfa.service.spec.ts` | ❌ W0 | ⬜ pending |
| 07-02-03 | 02 | 1 | MFA-05 | T-07-03 | validateMfaToken rejects expired token with 401 | unit | `npx jest src/mfa/__tests__/mfa.service.spec.ts` | ❌ W0 | ⬜ pending |
| 07-03-01 | 03 | 2 | MFA-01,MFA-06 | — | POST /mfa/initiate returns 201 with challengeId+expiresAt | e2e | `npx jest tests/integration/mfa.e2e-spec.ts` | ❌ W0 | ⬜ pending |
| 07-03-02 | 03 | 2 | MFA-08 | — | POST /mfa/initiate returns 429 after 5 requests in window | e2e | `npx jest tests/integration/mfa.e2e-spec.ts` | ❌ W0 | ⬜ pending |
| 07-03-03 | 03 | 2 | MFA-02 | T-07-01 | POST /mfa/verify returns MFA JWT on valid TOTP code | e2e | `npx jest tests/integration/mfa.e2e-spec.ts` | ❌ W0 | ⬜ pending |
| 07-03-04 | 03 | 2 | MFA-04 | T-07-02 | MfaGuard rejects X-MFA-Token with wrong fingerprint | unit | `npx jest src/mfa/__tests__/mfa.guard.spec.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/mfa/__tests__/mfa.service.spec.ts` — stubs for MFA-01 through MFA-08
- [ ] `src/mfa/__tests__/mfa.guard.spec.ts` — stubs for MfaGuard fingerprint + token validation
- [ ] `tests/integration/mfa.e2e-spec.ts` — e2e stubs for /mfa/initiate and /mfa/verify flows
- [ ] `src/shared/__tests__/aes-gcm.util.spec.ts` — encrypt/decrypt round-trip test

*All tests must exist (even as skipped stubs) before Wave 1 execution.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TOTP code window tolerance (±1 step) | MFA-02 | Requires real clock skew simulation | Generate code at step boundary; verify accepted in ±30s window |
| Encrypted TOTP secret at-rest in DB | MFA-07 | Requires DB inspection | `SELECT totp_secret_encrypted FROM user_secrets WHERE user_id = 'test'` — verify value is not plaintext base32 |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

## Sign-off rationale

Phase 07 (mfa-challenge) is Nyquist-compliant as of 2026-05-12 on the strength of pre-existing automated coverage; this sign-off is a process-only promotion (no new specs authored).

- **VERIFICATION.md score:** 19/19 (`.planning/phases/07-mfa-challenge/07-VERIFICATION.md`, status: human_needed — all automated must-haves verified; 5 items deferred to live UAT).
- **Milestone audit anchor:** `.planning/v1.0-MILESTONE-AUDIT.md` Phase Status Matrix row 07 records score 19/19 and confirms functional coverage is locked.
- **Deferred HUMAN-UAT carryover (non-blocking, per audit framing "automated must-haves verified"):** Item 3 (live POST /mfa/initiate→/verify happy path, rate-limit 429 with Retry-After, Joi bootstrap failures for MFA_JWT_SECRET / MFA_TOTP_ENCRYPTION_KEY / MFA_CHALLENGE_TTL_MS<MFA_TOKEN_TTL_MS).
- **Pre-flight gate (Phase 17 D-07):** Full unit + e2e suites green and `npm run lint` exit recorded in `.planning/phases/17-v1-0-nyquist-signoff-sweep/17-preflight.txt`.
