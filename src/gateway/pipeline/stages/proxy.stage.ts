import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { ProxyService } from '../../../proxy/proxy.service';

/**
 * Phase D Stage 11 — mTLS proxy forwarding (D-09).
 *
 * Calls ProxyService.forward(req, claims, trustScore) and stashes the
 * upstream status + body on ctx for the downstream BoplaStripStage and
 * RecordTrustContextStage. ServiceUnavailableException propagates to the
 * terminal handler (→ 502 proxy_unavailable).
 *
 * Returns `continue` rather than the terminal `proxied` outcome — bopla
 * stripping and trust-context recording still need ctx; the final stage in
 * the chain (RecordTrustContextStage) emits `proxied`.
 */
@Injectable()
export class ProxyStage implements PipelineStage {
  readonly id = 'proxy';

  constructor(private readonly proxy: ProxyService) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) throw new Error('ProxyStage: ctx.claims missing');
    if (ctx.trustScore === undefined) {
      throw new Error('ProxyStage: ctx.trustScore missing');
    }
    const upstream = await this.proxy.forward(ctx.req, ctx.claims, ctx.trustScore);
    ctx.upstreamStatus = upstream.status;
    ctx.upstreamBody = upstream.data;
    return { kind: 'continue' };
  }
}
