/**
 * Phase 7 — MfaService unit tests (MFA-01, MFA-02, MFA-03, MFA-04, MFA-06, MFA-08)
 * All tests are it.todo stubs; Wave 2 plan (07-02) fills in the implementations.
 */
describe('MfaService', () => {
  describe('createChallenge()', () => {
    it.todo('returns { challengeId, expiresAt } and inserts mfa_challenges row (MFA-01)');
    it.todo('returns rate_limited after MFA_RATE_LIMIT_MAX initiations in window (MFA-08)');
    it.todo('emits MFA_RATE_LIMITED (not MFA_FAILED) on rate-limit denial (D-18)');
  });

  describe('verifyTotp()', () => {
    it.todo('returns { ok: true, token, expiresAt } with MFA JWT typ:mfa for valid TOTP code (MFA-02, MFA-03)');
    it.todo('fingerprint is SHA-256(userId|deviceId|ip) stored in mfa_tokens.fingerprint_hash (MFA-04)');
    it.todo('returns { ok: false, reason: expired_challenge } for expired challenge row (MFA-01)');
    it.todo('returns { ok: false, reason: invalid_code } for wrong TOTP code (MFA-02)');
    it.todo('returns { ok: false, reason: unknown_user } when user has no secret in user_secrets (D-16)');
    it.todo('emits MFA_FAILED with reason on every failure (D-12)');
    it.todo('MFA JWT is HS256-signed with MFA_JWT_SECRET, not JWT_SECRET (MFA-03, D-09)');
    it.todo('MFA JWT carries jti, sub, deviceId, fpHash, typ:mfa, iat, exp (D-10)');
  });

  describe('validateMfaToken()', () => {
    it.todo('returns { ok: true, claims } for valid token with matching fingerprint (MFA-05)');
    it.todo('returns { ok: false, reason: signature } for tampered token signature (D-11)');
    it.todo('returns { ok: false, reason: expired } for expired token (MFA-07)');
    it.todo('returns { ok: false, reason: fingerprint_mismatch } for token from different IP (MFA-05, D-06)');
    it.todo('returns { ok: false, reason: revoked } for revoked jti (D-08)');
    it.todo('returns { ok: false, reason: unknown_jti } for jti not in mfa_tokens (D-11)');
    it.todo('returns { ok: false, reason: wrong_type } for token with typ!=mfa (D-10)');
    it.todo('emits MFA_FAILED on every validate failure (D-12)');
  });
});
