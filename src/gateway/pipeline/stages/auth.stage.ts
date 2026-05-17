import { Injectable, Logger } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { AuthService } from '../../../auth/auth.service';
import { AuditService } from '../../../audit/audit.service';
import { MetricsService } from '../../../metrics/metrics.service';
import { TypedEvents } from '../../../shared/typed-events';
import { AUTH_INVALID_TOKEN } from '../../../policy/policy-events';
import { buildAuthInvalidPayload } from '../../../auth/auth-invalid-payload';
import { GATEWAY_VALIDATED } from '../../../auth/gateway-validated.symbol';
import { extractIp } from '../../../shared/request-context.util';
import { recordWithTimeoutBestEffort } from '../record-with-timeout.util';

@Injectable()
export class AuthStage implements PipelineStage {
  readonly id = 'auth';
  private readonly logger = new Logger(AuthStage.name);
  constructor(
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
    private readonly events: TypedEvents,
  ) {}
  async run(ctx: StageContext): Promise<StageOutcome> {
    const o = await this.auth.authenticate(ctx.req);
    const { requestId } = ctx;
    if (o.kind === 'ok') {
      ctx.claims = o.claims;
      const r = ctx.req as typeof ctx.req & { user?: unknown; [GATEWAY_VALIDATED]?: true };
      r.user = o.claims;
      r[GATEWAY_VALIDATED] = true;
      return { kind: 'continue' };
    }
    await recordWithTimeoutBestEffort(this.audit, this.metrics, this.logger, {
      userId: 'anonymous',
      resource: ctx.reqPath,
      action: ctx.req.method,
      decision: 'deny',
      ja4hFingerprint: ctx.ja4h,
      ipAddress: extractIp(ctx.req),
      requestId,
    });
    if (o.kind === 'revoked')
      return { kind: 'short-circuit', status: 401, body: { error: 'token_revoked', requestId } };
    this.events.emit(AUTH_INVALID_TOKEN, buildAuthInvalidPayload(ctx.req));
    const body =
      o.reason === 'token'
        ? { error: 'auth_invalid', message: o.message, requestId }
        : { error: 'auth_required', requestId };
    return { kind: 'short-circuit', status: 401, body };
  }
}
