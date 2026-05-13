import { Injectable, Logger } from '@nestjs/common';
import { TypedEvents } from '../shared/typed-events';
import { MFA_INFRA_ERROR } from '../policy/policy-events';

/**
 * Phase C (260513-mar) — extracted from `MfaService.recordInfraError`.
 *
 * Centralised structured logging + observability emission for swallowed
 * infra errors. Operators previously saw zero signal when a Postgres outage
 * turned every MFA call into a silent { ok:false, reason:'internal' } — no
 * log, no event, no audit trail. Each catch site routes through this helper
 * so dashboards / alerts can fire on `mfa.infra_error` spikes.
 *
 * Generalised to take the calling service name (passed by the consumer) so
 * both `MfaChallenger` and `MfaEnroller` produce consistent log + event
 * shapes without duplicating the body.
 */
@Injectable()
export class MfaErrorRecorder {
  constructor(private readonly events: TypedEvents) {}

  record(serviceName: string, op: string, userId: string | undefined, err: unknown): void {
    // WR-NEW-01 (phase 14, iter2): NestJS Logger.error(message, stack?, context?)
    // expects the 2nd arg to be a string stack trace. Passing the raw Error
    // instance caused the framework to stringify it via String(err), collapsing
    // the full frame list to "Error: <msg>" and erasing every stack frame.
    const logger = new Logger(serviceName);
    const e =
      err instanceof Error ? err : new Error(typeof err === 'string' ? err : JSON.stringify(err));
    logger.error(`${serviceName}.${op} infra error: ${e.message}`, e.stack);
    this.events.emit(MFA_INFRA_ERROR, {
      userId,
      op,
      ts: Date.now(),
    });
  }
}
