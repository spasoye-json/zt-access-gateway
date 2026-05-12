import { Request } from 'express';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

function isValidIp(ip: string): boolean {
  return IPV4.test(ip) || IPV6.test(ip);
}

/**
 * Extracts the real client IP from request headers.
 * Takes ONLY the first entry from x-forwarded-for to prevent IP spoofing
 * via appended headers (T-01-04). The upstream proxy must set this header.
 * Validates the extracted value as an IPv4/IPv6 address to block injection
 * of arbitrary strings into trust scoring and audit logs (T-01-04).
 */
export function extractIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim();
    if (first && isValidIp(first)) return first;
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
