import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { extractIp } from '../shared/request-context.util';
import { AppConfigService } from '../config/config.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import type { TrustContext } from '../trust-score/trust-context';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { HashcashService } from './hashcash.service';

/**
 * Phase 5 — global PoW guard (D-06).
 * Pipeline position: AFTER JwtAuthGuard (Pitfall 2 — AppModule import order matters).
 *
 * D-07 seam: reads `request.trustScore` if set; otherwise calls TrustScoreService.evaluateScore
 * directly. Phase 10 GatewayMiddleware will populate `req.trustScore` upstream to avoid the duplicate.
 *
 * Skips: @Public() routes, OPTIONS preflight.
 *
 * Single source of truth (anti-bug): difficulty is determined ONLY inside HashcashService.
 * The guard destructures { nonce, difficulty, expiresAt } from issueChallenge and uses those
 * values directly in the response — it does NOT import or call any difficulty helper. This
 * eliminates the entire class of "header difficulty drifts from payload.diff" bugs.
 */
@Injectable()
export class HashcashGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly hashcash: HashcashService,
    private readonly trust: TrustScoreService,
    private readonly cfg: AppConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // 1. CORS preflight bypass (Claude's Discretion in D-18)
    if (request.method === 'OPTIONS') return true;

    // 2. @Public() bypass
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    // 3. Identity must be present (JwtAuthGuard ran first — Pitfall 2)
    const user = (request as Request & { user?: UserClaims }).user;
    if (!user || !user.userId || !user.deviceId) {
      throw new UnauthorizedException('Hashcash guard requires authenticated request');
    }

    // 4. Score acquisition: D-07 seam
    let score = request.trustScore;
    if (score === undefined) {
      const ja4h = (request.headers['x-ja4h'] as string) || '';
      const ctx: TrustContext = {
        userId: user.userId,
        deviceId: user.deviceId,
        ip: extractIp(request),
        ja4h,
      };
      score = await this.trust.evaluateScore(ctx);
    }

    // 5. Below threshold (strict > per D-08): pass through
    if (score <= this.cfg.hashcashTriggerThreshold) return true;

    // 6. High-risk path: issue or verify
    const nonceHeader = (request.headers['x-hashcash-nonce'] as string | undefined) || '';
    const solutionHeader =
      (request.headers['x-hashcash-solution'] as string | undefined) || '';

    if (!nonceHeader || !solutionHeader) {
      this.issueChallenge(response, user.userId, user.deviceId, score, 'proof_of_work_required');
      return false;
    }

    // 7. Header bomb defense (T-5-HBOMB) — service also enforces, but reject early to avoid misleading service metrics
    if (solutionHeader.length > 256 || solutionHeader.length < 1) {
      this.issueChallenge(response, user.userId, user.deviceId, score, 'proof_of_work_invalid');
      return false;
    }

    const result = this.hashcash.verifySolution(nonceHeader, solutionHeader, score);
    if (result.ok) return true;

    this.issueChallenge(response, user.userId, user.deviceId, score, 'proof_of_work_invalid');
    return false;
  }

  private issueChallenge(
    response: Response,
    userId: string,
    deviceId: string,
    score: number,
    error: 'proof_of_work_required' | 'proof_of_work_invalid',
  ): void {
    // Single source of truth: service computes difficulty + expiresAt and returns them.
    // Guard MUST NOT recompute — that path was the source of the NaN-in-header bug.
    const { nonce, difficulty, expiresAt } = this.hashcash.issueChallenge(userId, deviceId, score);
    response
      .status(429)
      .header('X-Hashcash-Challenge', `${nonce}:${difficulty}`)
      .header('Retry-After', '1')
      .json({ error, nonce, difficulty, expiresAt });
  }
}
