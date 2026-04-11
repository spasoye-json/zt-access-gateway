import { Request } from 'express';

/**
 * Extracts the real client IP from request headers.
 * Takes ONLY the first entry from x-forwarded-for to prevent IP spoofing
 * via appended headers (T-01-04). The upstream proxy must set this header.
 */
export function extractIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)
      .split(',')[0]
      .trim();
    return first;
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
