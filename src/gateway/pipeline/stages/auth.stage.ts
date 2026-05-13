import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { AuthService } from '../../../auth/auth.service';
import { TypedEvents } from '../../../shared/typed-events';
import { AUTH_INVALID_TOKEN } from '../../../policy/policy-events';
import { extractIp } from '../../../shared/request-context.util';

/**
 * Phase D Stage 3 — Bearer JWT validation (D-05 / WR-01).
 *
 * Emits AUTH_INVALID_TOKEN on every short-circuit so ThreatEscalationService
 * aggregates consistently across the gateway and JwtAuthGuard.
 *
 * - missing/non-string Authorization → 401 auth_required
 * - non-Bearer scheme OR empty token → 401 auth_required
 * - validateToken throws UnauthorizedException → 401 auth_invalid (message preserved)
 * - validateToken throws anything else → re-throw (propagates to handleTerminalError)
 */
@Injectable()
export class AuthStage implements PipelineStage {
  readonly id = 'auth';

  constructor(
    private readonly auth: AuthService,
    private readonly events: TypedEvents,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    const emitInvalid = (): void => {
      this.events.emit(AUTH_INVALID_TOKEN, {
        type: AUTH_INVALID_TOKEN,
        ip: extractIp(ctx.req),
        userId: ctx.claims?.userId,
        ja4h: ctx.ja4h,
        ts: Date.now(),
      });
    };

    const authHeader = ctx.req.headers['authorization'];
    if (!authHeader || typeof authHeader !== 'string') {
      emitInvalid();
      return {
        kind: 'short-circuit',
        status: 401,
        body: { error: 'auth_required', requestId: ctx.requestId },
      };
    }
    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) {
      emitInvalid();
      return {
        kind: 'short-circuit',
        status: 401,
        body: { error: 'auth_required', requestId: ctx.requestId },
      };
    }
    try {
      ctx.claims = await this.auth.validateToken(token);
    } catch (e) {
      if (e instanceof UnauthorizedException) {
        emitInvalid();
        return {
          kind: 'short-circuit',
          status: 401,
          body: {
            error: 'auth_invalid',
            message: (e as Error).message,
            requestId: ctx.requestId,
          },
        };
      }
      throw e;
    }
    return { kind: 'continue' };
  }
}
