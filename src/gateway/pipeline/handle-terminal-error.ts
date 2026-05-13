import { Logger, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import type { Response } from 'express';
import { AuditExhaustedException } from '../../audit/audit-exhausted.exception';
import { AUDIT_SIGNAL } from '../../policy/policy-events';
import { extractIp } from '../../shared/request-context.util';
import type { TypedEvents } from '../../shared/typed-events';
import type { MetricsService } from '../../metrics/metrics.service';
import type { StageContext } from './stage-context';

/**
 * Phase D — Terminal error handler for the pipeline.
 *
 * Ports the try/catch tail from the previous monolithic middleware
 * verbatim:
 *  - AuditExhaustedException → 503 + Retry-After:5; emit AUDIT_SIGNAL
 *  - ServiceUnavailableException → 502 proxy_unavailable
 *  - UnauthorizedException → 401 auth_invalid
 *  - anything else → re-throw (NestJS exception filter handles it)
 */
export function handleTerminalError(
  res: Response,
  e: unknown,
  ctx: StageContext,
  events: TypedEvents,
  metrics: MetricsService,
  _logger?: Logger,
): void {
  if (e instanceof AuditExhaustedException) {
    metrics.incrementAuditFailure();
    events.emit(AUDIT_SIGNAL, {
      type: AUDIT_SIGNAL,
      ip: extractIp(ctx.req),
      userId: ctx.claims?.userId,
      ja4h: ctx.ja4h,
      ts: Date.now(),
      resource: ctx.reqPath,
      action: ctx.req.method,
      requestId: ctx.requestId,
    });
    res
      .status(503)
      .set('Retry-After', '5')
      .json({ error: 'audit_unavailable', requestId: ctx.requestId });
    return;
  }
  if (e instanceof ServiceUnavailableException) {
    res.status(502).json({ error: 'proxy_unavailable', requestId: ctx.requestId });
    return;
  }
  if (e instanceof UnauthorizedException) {
    res.status(401).json({
      error: 'auth_invalid',
      message: (e as Error).message,
      requestId: ctx.requestId,
    });
    return;
  }
  throw e;
}
