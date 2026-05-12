import * as fs from 'fs';
import * as path from 'path';
import { HONEYPOT_PATHS } from '../honeypot.constants';

/**
 * Phase 10 Plan 02 (GTWY-09 / D-05 / D-16) —
 * HONEYPOT_PATHS is the single source of truth shared by ShadowController
 * (route registration) and Wave 2's GatewayMiddleware (O(1) bypass via
 * Set.has(req.path)). This spec locks the literal set + enforces parity
 * with shadow.controller.ts so future @Get() additions cannot drift.
 */
describe('HONEYPOT_PATHS', () => {
  const EXPECTED = [
    '/wp-login.php',
    '/.env',
    '/admin/config.json',
    '/api/v1/debug',
    '/graphql/introspection',
    '/actuator/health',
    '/api/v1/internal/keys',
  ];

  it('has exactly 7 entries', () => {
    expect(HONEYPOT_PATHS.size).toBe(7);
  });

  it('contains exactly the 7 expected decoy paths', () => {
    expect([...HONEYPOT_PATHS].sort()).toEqual([...EXPECTED].sort());
  });

  it('Set.has returns true for /wp-login.php', () => {
    expect(HONEYPOT_PATHS.has('/wp-login.php')).toBe(true);
  });

  it('Set.has returns false for /health (PUBLIC_PATH, not honeypot)', () => {
    expect(HONEYPOT_PATHS.has('/health')).toBe(false);
  });

  it('Set.has returns false for /metrics (PUBLIC_PATH, not honeypot)', () => {
    expect(HONEYPOT_PATHS.has('/metrics')).toBe(false);
  });

  it('Set.has does not strip query strings — consumer must pass req.path', () => {
    expect(HONEYPOT_PATHS.has('/api/v1/debug?x=1')).toBe(false);
  });

  it('parity: every @Get() decorator literal in shadow.controller.ts is in HONEYPOT_PATHS', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '../shadow.controller.ts'), 'utf8');
    // Match only decorator usage at start of a line (allowing leading whitespace),
    // not occurrences of @Get(...) embedded in comments.
    const decoratorPaths = [...src.matchAll(/^\s*@Get\('([^']+)'\)/gm)].map((m) => m[1]).sort();
    const constPaths = [...HONEYPOT_PATHS].sort();
    expect(decoratorPaths).toEqual(constPaths);
  });
});
