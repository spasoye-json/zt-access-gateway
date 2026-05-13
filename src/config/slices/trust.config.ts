import type { ConfigService } from '@nestjs/config';

/**
 * Trust scoring slice (Phase 4 D-21).
 */
export interface TrustConfig {
  readonly knownThreshold: number;
  readonly decayHalfLifeMs: number;
  readonly anomalyWarmupN: number;
  readonly frequencyWindowMs: number;
  readonly frequencyNormalMax: number;
}

export const TRUST_CONFIG = Symbol('TRUST_CONFIG');

export function buildTrustConfig(env: ConfigService): TrustConfig {
  return Object.freeze({
    knownThreshold: env.get<number>('TRUST_KNOWN_THRESHOLD'),
    decayHalfLifeMs: env.get<number>('TRUST_DECAY_HALFLIFE_MS'),
    anomalyWarmupN: env.get<number>('TRUST_ANOMALY_WARMUP_N'),
    frequencyWindowMs: env.get<number>('TRUST_FREQUENCY_WINDOW_MS'),
    frequencyNormalMax: env.get<number>('TRUST_FREQUENCY_NORMAL_MAX'),
  });
}
