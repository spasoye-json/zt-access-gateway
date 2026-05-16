import { Injectable, Logger } from '@nestjs/common';
import { FingerprintStore } from '../fingerprint/fingerprint.store';
import { TrustTelemetryRepository } from './trust-telemetry.repository';
import type { TrustContext } from './trust-context';
import type { TrustSignalProvider } from './trust-signal-provider.interface';
import { DeviceReputationProvider } from './providers/device-reputation.provider';
import { IpReputationProvider } from './providers/ip-reputation.provider';
import { Ja4hDriftProvider } from './providers/ja4h-drift.provider';
import { RequestFrequencyProvider } from './providers/request-frequency.provider';
import { TrustDecayProvider } from './providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from './providers/behavior-anomaly.provider';

@Injectable()
export class TrustScoreService {
  private readonly logger = new Logger(TrustScoreService.name);
  private readonly providers: TrustSignalProvider[];

  constructor(
    private readonly fingerprintStore: FingerprintStore,
    private readonly telemetry: TrustTelemetryRepository,
    deviceReputation: DeviceReputationProvider,
    ipReputation: IpReputationProvider,
    ja4hDrift: Ja4hDriftProvider,
    requestFrequency: RequestFrequencyProvider,
    trustDecay: TrustDecayProvider,
    behaviorAnomaly: BehaviorAnomalyProvider,
  ) {
    this.providers = [
      deviceReputation,
      ipReputation,
      ja4hDrift,
      requestFrequency,
      trustDecay,
      behaviorAnomaly,
    ];
  }

  /**
   * Non-terminal trust score in [0,1] (TRST-01). Terminal JA4H returns 1.0 without DB reads (D-06).
   */
  async evaluateScore(ctx: TrustContext): Promise<number> {
    if (this.fingerprintStore.isTerminal(ctx.ja4h)) {
      return 1;
    }

    const adjustments = await Promise.all(
      this.providers.map((p) =>
        p.compute(ctx).catch((err: unknown) => {
          const errMsg =
            err instanceof Error
              ? err.message
              : typeof err === 'string'
                ? err
                : JSON.stringify(err);
          this.logger.warn(`Trust provider fault ${p.name}: ${errMsg}`);
          return { source: p.name, delta: 0.1, reason: `${p.name}_fault`, decayable: false };
        }),
      ),
    );

    const deltaSum = adjustments.reduce((s, a) => s + a.delta, 0);
    return Math.min(1, Math.max(0, 0.5 + deltaSum));
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
