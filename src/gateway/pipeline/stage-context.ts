import type { Request, Response, NextFunction } from 'express';
import type { UserClaims } from '../../auth/interfaces/user-claims.interface';
import type { TrustContext } from '../../trust-score/trust-context';
import type { PolicyDecision } from '../../policy/policy-decision';

/**
 * Phase D — Shared mutable context threaded through every PipelineStage.
 *
 * Fields populated progressively: `req/res/next/requestId/startedAt/reqPath/ja4h`
 * are set by `buildStageContext` once at the top of the middleware; downstream
 * stages set `claims` (auth), `trustScore + trustCtx` (trust-score),
 * `policyDecision` (policy), `upstreamStatus + upstreamBody` (proxy), and
 * `strippedBody` (bopla-strip).
 *
 * Stages MUST NOT call `res.*` directly — they return a StageOutcome and the
 * middleware's `writeOutcome` helper performs the single response write.
 */
export interface StageContext {
  req: Request;
  res: Response;
  next: NextFunction;
  requestId: string;
  startedAt: number;
  reqPath: string;
  ja4h?: string;
  claims?: UserClaims;
  trustScore?: number;
  trustCtx?: TrustContext;
  policyDecision?: PolicyDecision;
  upstreamStatus?: number;
  upstreamBody?: unknown;
  strippedBody?: unknown;
}
