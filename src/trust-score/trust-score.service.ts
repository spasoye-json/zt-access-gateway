import { Inject, Injectable, Logger } from '@nestjs/common';
import { FingerprintStore } from '../fingerprint/fingerprint.store';
import { TRUST_CONFIG, type TrustConfig } from '../config/slices';
import { TypedEvents } from '../shared/typed-events';
import { TRUST_PROVIDER_FAULT } from '../metrics/metrics-events';
import { TrustTelemetryRepository } from './trust-telemetry.repository';
import type { TrustContext } from './trust-context';
import type { SignalAdjustment } from './trust-signal-provider.interface';
import { Ja4hDriftProvider } from './providers/ja4h-drift.provider';
import { TrustDecayProvider } from './providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from './providers/behavior-anomaly.provider';
import { SIGNAL_RULES_TOKEN } from './signal-rules.token';
import { evaluateRule, type SignalRule } from './signal-rules';

@Injectable()
export class TrustScoreService {
  private readonly logger = new Logger(TrustScoreService.name);

  constructor(
    private readonly fingerprintStore: FingerprintStore,
    private readonly telemetry: TrustTelemetryRepository,
    @Inject(TRUST_CONFIG) private readonly config: TrustConfig,
    @Inject(SIGNAL_RULES_TOKEN) private readonly rules: readonly SignalRule[],
    private readonly ja4hDrift: Ja4hDriftProvider,
    private readonly trustDecay: TrustDecayProvider,
    private readonly behaviorAnomaly: BehaviorAnomalyProvider,
    private readonly events: TypedEvents,
  ) {}

  /**
   * Non-terminal trust score in [0,1] (TRST-01). Terminal JA4H returns 1.0 without DB reads (D-06).
   */
  async evaluateScore(ctx: TrustContext): Promise<number> {
    if (this.fingerprintStore.isTerminal(ctx.ja4h)) {
      return 1;
    }

    // Phase 1: rules + custom providers in parallel.
    const ruleTasks = this.rules.map((rule) =>
      evaluateRule(rule, this.telemetry, this.config, ctx).catch((err: unknown) =>
        this.faultAdjustment(rule.name, err),
      ),
    );
    const providerTasks = [this.ja4hDrift, this.behaviorAnomaly].map((p) =>
      p.compute(ctx).catch((err: unknown) => this.faultAdjustment(p.name, err)),
    );
    const phase1 = await Promise.all([...ruleTasks, ...providerTasks]);

    // Phase 2: Trust Decay attenuates favourable decayable adjustments.
    const decayCorrection = await this.trustDecay
      .attenuate(ctx, phase1)
      .catch((err: unknown) => this.faultAdjustment(this.trustDecay.name, err));

    const deltaSum = [...phase1, decayCorrection].reduce((s, a) => s + a.delta, 0);
    return Math.min(1, Math.max(0, 0.5 + deltaSum));
  }

  private faultAdjustment(source: string, err: unknown): SignalAdjustment {
    const msg =
      err instanceof Error ? err.message : typeof err === 'string' ? err : JSON.stringify(err);
    this.logger.warn(`Trust signal fault ${source}: ${msg}`);
    this.events.emit(TRUST_PROVIDER_FAULT, { provider: source });
    return { source, delta: 0.1, reason: `${source}_fault`, decayable: false };
  }

  /**
   * Persist trust telemetry after a successful downstream proxy on ALLOW only.
   * Phase 10 GatewayMiddleware must **not** call this on CHALLENGE or DENY (TRST-09, D-19).
   */
  async recordTrustContextAfterAllow(ctx: TrustContext, finalScore: number): Promise<void> {
    if (Number.isNaN(finalScore)) {
      throw new Error('finalScore must be a finite number');
    }
    await this.telemetry.recordAllowOutcome(ctx, finalScore);
  }
}
