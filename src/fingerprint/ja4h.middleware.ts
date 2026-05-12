import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { FingerprintStore } from './fingerprint.store';
import { computeJa4h } from './ja4h.util';
import { sleep, randomDelay } from '../shared/sleep.util';

/**
 * Ja4hMiddleware — first stage of the zero-trust pipeline.
 *
 * 1. Computes the JA4H fingerprint from raw HTTP headers.
 * 2. Attaches it to req['x-ja4h'] for downstream modules (trust score, audit).
 * 3. If the fingerprint is blacklisted: tarpits the connection for 2-5 seconds
 *    (async sleep yields the event loop — D-05) then returns 403 Forbidden.
 *    Response body is generic to avoid revealing blacklist reason (T-02-04).
 * 4. Otherwise calls next() to continue the pipeline.
 */
@Injectable()
export class Ja4hMiddleware implements NestMiddleware {
  constructor(private readonly store: FingerprintStore) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const fingerprint = computeJa4h(req);
    (req as Request & { 'x-ja4h': string })['x-ja4h'] = fingerprint;

    if (this.store.isBlacklisted(fingerprint)) {
      // Tarpit: hold the connection briefly to slow down scanners (D-05, T-02-05)
      const delay = randomDelay(2000, 5000);
      await sleep(delay);
      res.status(403).json({ statusCode: 403, message: 'Forbidden' });
      return;
    }

    next();
  }
}
