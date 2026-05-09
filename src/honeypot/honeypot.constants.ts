/**
 * Phase 10 — Honeypot decoy paths (D-05, D-16, GTWY-09).
 *
 * Single source of truth for both ShadowController route registration and
 * GatewayMiddleware path-based bypass. Wave 2's GatewayMiddleware uses
 * `HONEYPOT_PATHS.has(req.path)` for O(1) lookup before pipeline dispatch.
 *
 * IMPORTANT (Pitfall 6): GatewayMiddleware imports this constant statically;
 * it does NOT import HoneypotModule (which would create a NestJS DI cycle
 * via ShadowController's transitive dependencies on FingerprintStore).
 *
 * The 7 paths match the 7 @Get('...') decorators in shadow.controller.ts
 * exactly — a parity test enforces this invariant in __tests__/.
 */
export const HONEYPOT_PATHS: ReadonlySet<string> = new Set([
  '/wp-login.php',
  '/.env',
  '/admin/config.json',
  '/api/v1/debug',
  '/graphql/introspection',
  '/actuator/health',
  '/api/v1/internal/keys',
]);
