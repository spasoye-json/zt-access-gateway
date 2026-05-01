/**
 * Phase 7 — MFA e2e tests (MFA-06, MFA-08, MFA-02, MFA-04)
 * Wave 3 plan (07-03) fills in implementations.
 *
 * Note: uses tests/jest-e2e.json config (npm run test:e2e).
 */
describe('MFA HTTP e2e', () => {
  describe('POST /mfa/initiate', () => {
    it.todo('returns 201 with { challengeId, expiresAt } for authenticated user (MFA-06)');
    it.todo('returns 401 when no Authorization header present');
    it.todo('returns 429 with Retry-After after 5 initiations in 60s window (MFA-08)');
    it.todo('rate-limit emits MFA_RATE_LIMITED (not MFA_FAILED) event (D-18)');
  });

  describe('POST /mfa/verify', () => {
    it.todo('returns 200 with { token, expiresAt } for valid TOTP code (MFA-02, MFA-03)');
    it.todo('returns 401 for invalid TOTP code');
    it.todo('returns 401 for non-existent or expired challengeId');
    it.todo('MFA JWT in response has typ:mfa and is signed with MFA_JWT_SECRET (MFA-03)');
    it.todo('MFA JWT fingerprint hash is SHA-256(userId|deviceId|ip) (MFA-04)');
  });

  describe('MfaGuard — X-MFA-Token header', () => {
    it.todo('valid X-MFA-Token from same IP/device passes guard (MFA-05)');
    it.todo('X-MFA-Token replayed from different IP returns 401 fingerprint_mismatch (MFA-05, D-06)');
  });
});
