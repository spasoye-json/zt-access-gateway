import { createHash } from 'crypto';
import { Request } from 'express';

/**
 * Computes a JA4H fingerprint from an HTTP request.
 *
 * JA4H captures the client's HTTP "style" — method, protocol version, header
 * names in original casing and order, accept, and content-type. The resulting
 * SHA-256 hex uniquely identifies the client's HTTP stack, not its identity.
 *
 * Input format: "METHOD|httpVersion|HeaderName1,HeaderName2,...|accept|content-type"
 *
 * Uses rawHeaders (even indices) to preserve original header name casing and order
 * as sent by the client (JA4H-01). The parsed req.headers object normalises keys
 * to lowercase, so it is only used for value lookups (JA4H-02).
 */
export function computeJa4h(req: Request): string {
  // Extract header names from rawHeaders preserving casing and order (JA4H-01)
  const headerNames: string[] = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    headerNames.push(req.rawHeaders[i]);
  }

  const accept = req.headers['accept'] ?? '';
  const contentType = req.headers['content-type'] ?? '';
  // req.httpVersion is set by Node.js http.IncomingMessage; fall back to '1.1' in tests
  const httpVersion = (req as Request & { httpVersion?: string }).httpVersion ?? '1.1';

  const input = [req.method, httpVersion, headerNames.join(','), accept, contentType].join('|');

  return createHash('sha256').update(input).digest('hex');
}
