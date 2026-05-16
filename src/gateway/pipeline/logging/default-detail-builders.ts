import type { StageDetailRegistry } from './stage-detail-registry';

/**
 * Phase Demo — populate the StageDetailRegistry with builders for every
 * non-silent pipeline stage. Each builder is a pure function from
 * (ctx, outcome) -> kv map; the registry hands the map to the formatter.
 *
 * Builders default to {} when the upstream stage has not yet populated
 * the context field they need, so partial-pipeline runs (e.g. an auth
 * short-circuit) still render correctly.
 */
export function registerDefaultDetailBuilders(registry: StageDetailRegistry): void {
  registry.register('auth', (ctx) => {
    const c = ctx.claims;
    if (!c) return {};
    return {
      user: c.userId,
      roles: `[${c.roles.join(',')}]`,
    };
  });

  registry.register('revocation', (ctx) => {
    const jti = ctx.claims?.jti;
    return jti ? { jti } : {};
  });

  registry.register('trust_score', (ctx) => {
    if (typeof ctx.trustScore !== 'number') return {};
    const out: Record<string, string> = { score: ctx.trustScore.toFixed(2) };
    if (ctx.trustOverride === 'demo') out.override = 'demo';
    return out;
  });

  registry.register('hashcash', (_ctx, outcome) => {
    if (outcome.kind === 'short-circuit') return { challenge: 'required' };
    return {};
  });

  registry.register('policy', (ctx) => {
    const pd = ctx.policyDecision;
    if (!pd) return {};
    const out: Record<string, string> = { decision: pd.decision };
    if (pd.matchedSubject) out.subject = pd.matchedSubject;
    return out;
  });

  registry.register('mfa_promotion', (ctx, outcome) => {
    const pd = ctx.policyDecision;
    if (outcome.kind === 'short-circuit') return { mfa: 'required' };
    if (pd?.decision === 'ALLOW') return { mfa: 'ok' };
    return {};
  });

  registry.register('proxy', (ctx) => {
    if (typeof ctx.upstreamStatus !== 'number') return {};
    return { upstream: String(ctx.upstreamStatus) };
  });

  registry.register('bopla_strip', (ctx) => {
    return ctx.strippedBody !== undefined ? { stripped: 'yes' } : {};
  });

  registry.register('public_bypass', (_ctx, outcome) => {
    return outcome.kind === 'bypass' ? { public: 'true' } : {};
  });

  registry.register('honeypot_bypass', (_ctx, outcome) => {
    return outcome.kind === 'short-circuit' ? { honeypot: 'hit' } : {};
  });

  registry.register('auth_only', () => ({}));
}
