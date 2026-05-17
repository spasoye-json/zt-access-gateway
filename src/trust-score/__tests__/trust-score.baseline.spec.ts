import type { Pool } from 'pg';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TypedEvents } from '../../shared/typed-events';
import { FingerprintStore } from '../../fingerprint/fingerprint.store';
import type { ServerConfig, TrustConfig } from '../../config/slices';
import { DbService } from '../../db/db.service';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { TrustScoreService } from '../trust-score.service';
import { Ja4hDriftProvider } from '../providers/ja4h-drift.provider';
import { TrustDecayProvider } from '../providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from '../providers/behavior-anomaly.provider';
import { SIGNAL_RULES, evaluateRule } from '../signal-rules';
import type { TrustContext } from '../trust-context';

function ztTestUrlFromEnv(): string {
  const raw = process.env.DATABASE_URL;
  const u = new URL(raw);
  u.pathname = '/zt_test';
  return u.href;
}

interface CombinedConfigMock extends ServerConfig, TrustConfig {}

function mockConfig(url: string): CombinedConfigMock {
  return {
    databaseUrl: url,
    dbPoolMax: 3,
    knownThreshold: 3,
    decayHalfLifeMs: 604800000,
    anomalyWarmupN: 20,
    frequencyWindowMs: 60000,
    frequencyNormalMax: 30,
  } as unknown as CombinedConfigMock;
}

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

/**
 * Issue #13: fresh-device baseline.
 *
 * On an empty DB the per-provider math predicts:
 *   0.5 + 0.15(device_unknown) + 0.15(ip_untrusted)
 *       - 0.05(ja4h_stable) - 0.10(frequency_normal)
 *       + 0(trust_decay_none) + 0(anomaly_warmup) = 0.65
 */
describeDb('TrustScoreService fresh-device baseline (issue #13)', () => {
  const uidPrefix = 'tr-baseline-';
  let dbService: DbService;
  let pool: Pool;
  let service: TrustScoreService;
  let repository: TrustTelemetryRepository;
  let ja4hDrift: Ja4hDriftProvider;
  let trustDecay: TrustDecayProvider;
  let behaviorAnomaly: BehaviorAnomalyProvider;
  let config: CombinedConfigMock;

  beforeAll(() => {
    const url = ztTestUrlFromEnv();
    config = mockConfig(url);
    const fingerprintStore = new FingerprintStore(new TypedEvents(new EventEmitter2()));
    dbService = new DbService(config);
    pool = dbService.unsafePool();
    repository = new TrustTelemetryRepository(dbService);
    ja4hDrift = new Ja4hDriftProvider(repository, new TypedEvents(new EventEmitter2()));
    trustDecay = new TrustDecayProvider(repository, config);
    behaviorAnomaly = new BehaviorAnomalyProvider(repository, config);
    service = new TrustScoreService(
      fingerprintStore,
      repository,
      config,
      SIGNAL_RULES,
      ja4hDrift,
      trustDecay,
      behaviorAnomaly,
    );
  });

  afterAll(async () => {
    await dbService.onModuleDestroy();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM trust_activity WHERE user_id LIKE $1`, [`${uidPrefix}%`]);
    await pool.query(`DELETE FROM trust_signals WHERE user_id LIKE $1`, [`${uidPrefix}%`]);
  });

  it('returns 0.65 ± 0.01 for a fresh user/device/IP triple on an empty DB', async () => {
    const ctx: TrustContext = {
      userId: `${uidPrefix}alice`,
      deviceId: 'dev-fresh',
      ip: '203.0.113.7',
      ja4h: 'ja4h-fresh-baseline',
      requestTimestamp: new Date(),
    };

    const score = await service.evaluateScore(ctx);

    expect(score).toBeGreaterThanOrEqual(0.64);
    expect(score).toBeLessThanOrEqual(0.66);
  });

  it('all six providers return their documented empty-state reasons on an empty DB', async () => {
    const ctx: TrustContext = {
      userId: `${uidPrefix}bob`,
      deviceId: 'dev-empty-state',
      ip: '203.0.113.8',
      ja4h: 'ja4h-empty-state',
      requestTimestamp: new Date(),
    };

    const byName = new Map(SIGNAL_RULES.map((r) => [r.name, r]));
    const deviceRep = await evaluateRule(byName.get('device_reputation'), repository, config, ctx);
    const ipRep = await evaluateRule(byName.get('ip_reputation'), repository, config, ctx);
    const freq = await evaluateRule(byName.get('request_frequency'), repository, config, ctx);
    const ja4h = await ja4hDrift.compute(ctx);
    const anomaly = await behaviorAnomaly.compute(ctx);
    const decay = await trustDecay.attenuate(ctx, [deviceRep, ipRep, freq, ja4h, anomaly]);

    expect(deviceRep.reason).toBe('device_unknown');
    expect(ipRep.reason).toBe('ip_untrusted');
    expect(freq.reason).toBe('frequency_normal');
    expect(ja4h.reason).toBe('ja4h_stable');
    expect(anomaly.reason).toBe('anomaly_warmup');
    expect(decay.reason).toBe('trust_decay_none');
  });
});
