import { Inject, Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { HashcashService } from '../../../hashcash/hashcash.service';
import { HASHCASH_CONFIG, type HashcashConfig } from '../../../config/slices';

/**
 * Phase D Stage 7 — Hashcash proof-of-work gate (D-08).
 *
 * Only enforced when `ctx.trustScore > cfg.triggerThreshold` (default 0.5).
 * Three short-circuit branches:
 *   1. missing X-Hashcash-Nonce or X-Hashcash-Solution → 429 proof_of_work_required
 *   2. solution length out of [1, 256] → 429 proof_of_work_invalid
 *   3. verifySolution !ok → 429 proof_of_work_invalid
 *
 * Every short-circuit issues a fresh challenge via HashcashService and emits
 * X-Hashcash-Challenge + Retry-After:1 headers.
 *
 * Behaviour change vs. inline: the inline body emitted `observe('hashcash',
 * ...)` TWICE on the short-circuit path (once when issuing, once on the
 * fall-through). The orchestrator records exactly ONE timing per stage
 * invocation — this is a cleaner metric semantics and a documented Phase D
 * change.
 */
@Injectable()
export class HashcashStage implements PipelineStage {
  readonly id = 'hashcash';

  constructor(
    private readonly hashcash: HashcashService,
    @Inject(HASHCASH_CONFIG) private readonly cfg: HashcashConfig,
  ) {}

  // eslint-disable-next-line @typescript-eslint/require-await
  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) {
      throw new Error('HashcashStage: ctx.claims missing');
    }
    const trustScoreValue = ctx.trustScore;
    if (trustScoreValue === undefined) {
      throw new Error('HashcashStage: ctx.trustScore missing');
    }
    const threshold = this.cfg.triggerThreshold ?? 0.5;
    if (trustScoreValue <= threshold) {
      return { kind: 'continue' };
    }

    const claims = ctx.claims;
    const nonceHeader = (ctx.req.headers['x-hashcash-nonce'] as string | undefined) || '';
    const solutionHeader = (ctx.req.headers['x-hashcash-solution'] as string | undefined) || '';

    const issue = (errCode: 'proof_of_work_required' | 'proof_of_work_invalid'): StageOutcome => {
      const { nonce, difficulty, expiresAt } = this.hashcash.issueChallenge(
        claims.userId,
        claims.deviceId || '',
        trustScoreValue,
      );
      return {
        kind: 'short-circuit',
        status: 429,
        body: {
          error: errCode,
          nonce,
          difficulty,
          expiresAt,
          requestId: ctx.requestId,
        },
        headers: {
          'X-Hashcash-Challenge': `${nonce}:${difficulty}`,
          'Retry-After': '1',
        },
      };
    };

    if (!nonceHeader || !solutionHeader) {
      return issue('proof_of_work_required');
    }
    if (solutionHeader.length > 256 || solutionHeader.length < 1) {
      return issue('proof_of_work_invalid');
    }
    const r = this.hashcash.verifySolution(
      nonceHeader,
      solutionHeader,
      trustScoreValue,
      claims.userId,
      claims.deviceId || '',
    );
    if (!r.ok) {
      return issue('proof_of_work_invalid');
    }
    return { kind: 'continue' };
  }
}
