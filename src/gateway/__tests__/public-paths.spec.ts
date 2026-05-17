import { PUBLIC_PATHS, AUTH_ONLY_EXACT, AUTH_ONLY_PREFIXES, isAuthOnlyPath } from '../public-paths';

describe('public-paths', () => {
  it('PUBLIC_PATHS contains exactly /health and /metrics', () => {
    expect([...PUBLIC_PATHS].sort()).toEqual(['/health', '/metrics']);
  });

  it('AUTH_ONLY_EXACT contains the auth-only routes including /demo/mfa-token (Slice E)', () => {
    expect([...AUTH_ONLY_EXACT].sort()).toEqual(
      [
        '/audit/logs',
        '/auth/revoke',
        '/demo/mfa-token',
        '/mfa/enroll',
        '/mfa/enroll/confirm',
        '/mfa/initiate',
        '/mfa/verify',
      ].sort(),
    );
  });

  it('isAuthOnlyPath returns true for /demo/mfa-token (Slice E — bypass trust/hashcash so users at CHALLENGE can mint MFA)', () => {
    expect(isAuthOnlyPath('/demo/mfa-token')).toBe(true);
  });

  it('AUTH_ONLY_PREFIXES contains /mfa/admin/enrollment and /policy/admin', () => {
    expect([...AUTH_ONLY_PREFIXES].sort()).toEqual(
      ['/mfa/admin/enrollment', '/policy/admin'].sort(),
    );
  });

  it('isAuthOnlyPath returns true for /auth/revoke (exact)', () => {
    expect(isAuthOnlyPath('/auth/revoke')).toBe(true);
  });

  it('isAuthOnlyPath returns true for /mfa/admin/enrollment (exact prefix match)', () => {
    expect(isAuthOnlyPath('/mfa/admin/enrollment')).toBe(true);
  });

  it('isAuthOnlyPath returns true for /mfa/admin/enrollment/user-123 (prefix child)', () => {
    expect(isAuthOnlyPath('/mfa/admin/enrollment/user-123')).toBe(true);
  });

  it('isAuthOnlyPath returns false for /api/users', () => {
    expect(isAuthOnlyPath('/api/users')).toBe(false);
  });

  it('isAuthOnlyPath returns false for /health', () => {
    expect(isAuthOnlyPath('/health')).toBe(false);
  });

  it('isAuthOnlyPath returns false for /metrics', () => {
    expect(isAuthOnlyPath('/metrics')).toBe(false);
  });

  it('isAuthOnlyPath returns false for /wp-login.php', () => {
    expect(isAuthOnlyPath('/wp-login.php')).toBe(false);
  });

  it('isAuthOnlyPath returns true for /mfa/initiate (exact set member)', () => {
    expect(isAuthOnlyPath('/mfa/initiate')).toBe(true);
  });

  it('isAuthOnlyPath returns false for /mfa (over-match guard)', () => {
    expect(isAuthOnlyPath('/mfa')).toBe(false);
  });

  it('isAuthOnlyPath returns true for /audit/logs (exact set member, Phase 12)', () => {
    expect(isAuthOnlyPath('/audit/logs')).toBe(true);
  });

  it('isAuthOnlyPath returns true for /policy/admin (exact prefix match, Phase 12)', () => {
    expect(isAuthOnlyPath('/policy/admin')).toBe(true);
  });

  it('isAuthOnlyPath returns true for /policy/admin/rules (prefix child, Phase 12)', () => {
    expect(isAuthOnlyPath('/policy/admin/rules')).toBe(true);
  });

  it('isAuthOnlyPath returns true for /policy/admin/escalation (prefix child, Phase 12)', () => {
    expect(isAuthOnlyPath('/policy/admin/escalation')).toBe(true);
  });

  it('isAuthOnlyPath returns false for /policy (over-match guard, Phase 12)', () => {
    expect(isAuthOnlyPath('/policy')).toBe(false);
  });

  it('isAuthOnlyPath returns false for /audit (over-match guard, Phase 12)', () => {
    expect(isAuthOnlyPath('/audit')).toBe(false);
  });
});
