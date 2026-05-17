import type { Request } from 'express';
import { buildAuthInvalidPayload } from '../auth-invalid-payload';
import { AUTH_INVALID_TOKEN } from '../../policy/policy-events';

/**
 * Issue #16 — shared emission helper. Both adapters (AuthStage, JwtAuthGuard)
 * will call this so AUTH_INVALID_TOKEN payloads stay byte-identical across
 * seams. Closes the 13-REVIEW.md WARNING about emission drift.
 *
 * Behaviour mirrored from the current adapter emit sites:
 *   - type     = AUTH_INVALID_TOKEN
 *   - ip       = extractIp(req)        (x-forwarded-for first, validated)
 *   - ja4h     = extractJa4h(req)      (the Ja4hMiddleware-attached prop)
 *   - ts       = Date.now()
 */
describe('buildAuthInvalidPayload', () => {
  function fakeReq(overrides: {
    forwarded?: string | string[];
    socketIp?: string;
    ja4h?: string;
  }): Request {
    const req = {
      headers: overrides.forwarded ? { 'x-forwarded-for': overrides.forwarded } : {},
      socket: { remoteAddress: overrides.socketIp ?? '10.0.0.1' },
    } as unknown as Record<string, unknown>;
    if (overrides.ja4h !== undefined) req['x-ja4h'] = overrides.ja4h;
    return req as unknown as Request;
  }

  it('produces { type, ip, ja4h, ts } with type=AUTH_INVALID_TOKEN', () => {
    const before = Date.now();
    const p = buildAuthInvalidPayload(fakeReq({ forwarded: '203.0.113.7', ja4h: 'abc-def' }));
    const after = Date.now();

    expect(p.type).toBe(AUTH_INVALID_TOKEN);
    expect(p.ip).toBe('203.0.113.7');
    expect(p.ja4h).toBe('abc-def');
    expect(p.ts).toBeGreaterThanOrEqual(before);
    expect(p.ts).toBeLessThanOrEqual(after);
  });

  it('falls back to socket.remoteAddress when x-forwarded-for is absent', () => {
    const p = buildAuthInvalidPayload(fakeReq({ socketIp: '198.51.100.4' }));
    expect(p.ip).toBe('198.51.100.4');
  });

  it('leaves ja4h undefined when Ja4hMiddleware has not set it', () => {
    const p = buildAuthInvalidPayload(fakeReq({ socketIp: '198.51.100.4' }));
    expect(p.ja4h).toBeUndefined();
  });
});
