import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { AuthService } from '../../../auth/auth.service';
import { TypedEvents } from '../../../shared/typed-events';
import { AUTH_INVALID_TOKEN } from '../../../policy/policy-events';
import { buildAuthInvalidPayload } from '../../../auth/auth-invalid-payload';
import { GATEWAY_VALIDATED } from '../../../auth/gateway-validated.symbol';

@Injectable()
export class AuthStage implements PipelineStage {
  readonly id = 'auth';
  constructor(
    private readonly auth: AuthService,
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
