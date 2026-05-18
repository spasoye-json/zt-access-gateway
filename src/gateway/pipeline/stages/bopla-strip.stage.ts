import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { BoPlaInterceptor } from '../../../proxy/bopla.interceptor';

/**
 * Phase D Stage 12 — BOPLA response stripping (GTWY-06).
 *
 * Applies field-level policy to the upstream response body based on the
 * caller's roles. Admin-always-allow (Phase 8 D-07) is preserved by the
 * underlying BoPlaInterceptor.
 */
@Injectable()
export class BoplaStripStage implements PipelineStage {
  readonly id = 'bopla_strip';

  constructor(private readonly boPla: BoPlaInterceptor) {}

  run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) throw new Error('BoplaStripStage: ctx.claims missing');
    ctx.strippedBody = this.boPla.strip(ctx.upstreamBody, ctx.reqPath, ctx.claims.roles ?? []);
    const removed = diffTopLevelKeys(ctx.upstreamBody, ctx.strippedBody);
    if (removed.length > 0) ctx.boplaRemoved = removed;
    return Promise.resolve({ kind: 'continue' });
  }
}

function diffTopLevelKeys(before: unknown, after: unknown): string[] {
  if (!isPlainObject(before) || !isPlainObject(after)) return [];
  const afterKeys = new Set(Object.keys(after));
  return Object.keys(before).filter((k) => !afterKeys.has(k));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
