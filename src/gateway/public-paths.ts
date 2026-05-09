/**
 * Phase 10 -- Path-based dispatch constants for GatewayMiddleware (D-03, D-04, D-16).
 *
 * PUBLIC_PATHS: full pipeline bypass -- no auth, no trust, no policy, no audit.
 * AUTH_ONLY_*: run JA4H + auth + revocation only, then next() to controller.
 * isAuthOnlyPath: prefix-aware matcher for /mfa/admin/enrollment/:userId (D-04).
 *
 * Caller MUST pass req.path (not req.url) -- query strings are not handled here
 * (Pitfall 3 of 10-RESEARCH.md). All matches are case-sensitive (Express default).
 */
export const PUBLIC_PATHS: ReadonlySet<string> = new Set(['/health', '/metrics']);

export const AUTH_ONLY_EXACT: ReadonlySet<string> = new Set([
  '/auth/revoke',
  '/mfa/initiate',
  '/mfa/verify',
  '/mfa/enroll',
  '/mfa/enroll/confirm',
]);

export const AUTH_ONLY_PREFIXES: readonly string[] = ['/mfa/admin/enrollment'];

export function isAuthOnlyPath(p: string): boolean {
  if (AUTH_ONLY_EXACT.has(p)) return true;
  return AUTH_ONLY_PREFIXES.some((prefix) => p === prefix || p.startsWith(prefix + '/'));
}
