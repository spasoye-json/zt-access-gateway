import { Request } from 'express';
import { isIP } from 'node:net';

/**
 * Extracts the real client IP from request headers.
 * Takes ONLY the first entry from x-forwarded-for to prevent IP spoofing
 * via appended headers (T-01-04). The upstream proxy must set this header.
 * Validates the extracted value via Node's net.isIP (RFC 5952-compliant)
 * to block injection of arbitrary strings — including malformed IPv4
 * (e.g. "999.999.999.999") and bare hex tokens that the previous
 * permissive regex accepted (WR-02) — into trust scoring and audit logs.
 */
export function extractIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)
      .split(',')[0]
      .trim();
    if (first && isIP(first) !== 0) return first;
  }
  return req.socket?.remoteAddress || 'unknown';
}

/**
 * Extracts the User-Agent header value or returns 'unknown'.
 */
export function extractUserAgent(req: Request): string {
  return (req.headers['user-agent'] as string) || 'unknown';
}

/**
 * Extracts the x-device-id header value or returns null if absent.
 */
export function extractDeviceId(req: Request): string | null {
  return (req.headers['x-device-id'] as string) || null;
}

/**
 * Extracts the JA4H fingerprint attached by Ja4hMiddleware (Phase 2).
 *
 * IMPORTANT: Ja4hMiddleware writes to `(req as any)['x-ja4h']` — see
 * `src/fingerprint/ja4h.middleware.ts:23`. It does NOT set
 * `req.headers['x-ja4h']`. Reading from headers will silently return undefined
 * and produce empty fingerprint payloads in audit / threat signals.
 *
 * Returns undefined when absent so callers can decide their own fallback
 * (`?? 'unknown'` for trust ctx, `?? undefined` for ThreatSignalPayload).
 */
export function extractJa4h(req: Request): string | undefined {
  const v = (req as unknown as Record<string, unknown>)['x-ja4h'];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}
