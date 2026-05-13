import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import type { StageContext } from './stage-context';

/**
 * Phase D — Builds the initial StageContext at the top of every request.
 *
 * `reqPath` derivation is copied verbatim from the previous monolithic
 * middleware: NestJS `consumer.apply(...).forRoutes('*')` mounts the
 * middleware as a sub-app per matched route, so `req.path` becomes '/' and
 * the matched route lives in `req.baseUrl`. We therefore prefer
 * `req.originalUrl`, strip any query string, and fall back to `req.path` for
 * bare mock requests in unit tests.
 */
export function buildStageContext(req: Request, res: Response, next: NextFunction): StageContext {
  const requestId = (req.headers['x-request-id'] as string | undefined) ?? randomUUID();
  const ja4h = (req as unknown as Record<string, unknown>)['x-ja4h'] as string | undefined;
  const raw = req.originalUrl ?? req.url ?? req.path;
  const q = raw.indexOf('?');
  const reqPath = q >= 0 ? raw.slice(0, q) : raw;

  return {
    req,
    res,
    next,
    requestId,
    startedAt: Date.now(),
    reqPath,
    ja4h,
  };
}
