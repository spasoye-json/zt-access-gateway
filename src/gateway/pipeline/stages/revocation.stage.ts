import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { TokenRevocationService } from '../../../auth/token-revocation.service';
import type {
  UserClaims,
  AuthenticatedClaims,
} from '../../../auth/interfaces/user-claims.interface';

/**
 * Phase D Stage 4 — Token revocation check (D-06).
 *
 * On revoked JTI → 401 token_revoked. On clear → write the Phase A2 branded
 * req.user (`__authenticatedByGateway: true`) so JwtAuthGuard can detect a
 * gateway-authenticated request and skip re-validation.
 *
 * Ordering invariant: brand is attached AFTER isRevoked() clears (D-08).
 */
@Injectable()
export class RevocationStage implements PipelineStage {
  readonly id = 'revocation';

  constructor(private readonly revocation: TokenRevocationService) {}

  // eslint-disable-next-line @typescript-eslint/require-await
  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) {
      throw new Error('RevocationStage: ctx.claims missing (stage ordering bug)');
    }
    const claims = ctx.claims;
    if (this.revocation.isRevoked(claims.jti)) {
      return {
        kind: 'short-circuit',
        status: 401,
        body: { error: 'token_revoked', requestId: ctx.requestId },
      };
    }
    (ctx.req as Request & { user?: UserClaims | AuthenticatedClaims }).user = {
      ...claims,
      __authenticatedByGateway: true,
    };
    return { kind: 'continue' };
  }
}
