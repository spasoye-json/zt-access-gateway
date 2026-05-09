import {
  PUBLIC_PATHS,
  AUTH_ONLY_EXACT,
  AUTH_ONLY_PREFIXES,
  isAuthOnlyPath,
} from '../public-paths';

describe('public-paths', () => {
  it('PUBLIC_PATHS contains exactly /health and /metrics', () => {
    expect([...PUBLIC_PATHS].sort()).toEqual(['/health', '/metrics']);
  });

  it('AUTH_ONLY_EXACT contains exactly the five auth-only routes', () => {
    expect([...AUTH_ONLY_EXACT].sort()).toEqual(
      [
        '/auth/revoke',
        '/mfa/initiate',
        '/mfa/verify',
        '/mfa/enroll',
        '/mfa/enroll/confirm',
      ].sort(),
    );
  });

  it('AUTH_ONLY_PREFIXES contains /mfa/admin/enrollment', () => {
    expect([...AUTH_ONLY_PREFIXES]).toEqual(['/mfa/admin/enrollment']);
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
});
