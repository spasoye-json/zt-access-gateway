/**
 * Phase 7 — MfaGuard unit tests (MFA-05, D-06, D-20)
 * Wave 3 plan (07-03) fills in implementations.
 */
describe('MfaGuard', () => {
  it.todo('passes through when @Public() is set on handler');
  it.todo('throws UnauthorizedException({ error: mfa_required }) when X-MFA-Token header absent');
  it.todo('attaches result.claims to request.mfaToken and returns true on valid token');
  it.todo('throws UnauthorizedException({ error: mfa_invalid, reason: fingerprint_mismatch }) on mismatched fingerprint (MFA-05)');
  it.todo('throws UnauthorizedException({ error: mfa_invalid, reason: expired }) for expired token');
  it.todo('throws UnauthorizedException({ error: mfa_invalid, reason: revoked }) for revoked token');
});
