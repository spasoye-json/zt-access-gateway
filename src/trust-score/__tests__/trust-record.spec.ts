import { Pool } from 'pg';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TypedEvents } from '../../shared/typed-events';
import { FingerprintStore } from '../../fingerprint/fingerprint.store';
import type { ServerConfig, TrustConfig } from '../../config/slices';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { TrustScoreService } from '../trust-score.service';
import { DeviceReputationProvider } from '../providers/device-reputation.provider';
import { IpReputationProvider } from '../providers/ip-reputation.provider';
import { Ja4hDriftProvider } from '../providers/ja4h-drift.provider';
import { RequestFrequencyProvider } from '../providers/request-frequency.provider';
import { TrustDecayProvider } from '../providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from '../providers/behavior-anomaly.provider';
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
    knownThreshold: 3,
    decayHalfLifeMs: 604800000,
    anomalyWarmupN: 20,
    frequencyWindowMs: 60000,
    frequencyNormalMax: 30,
  } as unknown as CombinedConfigMock;
}

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('TRST-09 trust persistence boundary', () => {
  const uidPrefix = 'tr-record-';
  let pool: Pool;
  let repository: TrustTelemetryRepository;
  let service: TrustScoreService;
  let fingerprintStore: FingerprintStore;

  beforeAll(() => {
    const url = ztTestUrlFromEnv();
    const config = mockConfig(url);
    fingerprintStore = new FingerprintStore(new TypedEvents(new EventEmitter2()));
    repository = new TrustTelemetryRepository(config);
    service = new TrustScoreService(
      fingerprintStore,
      repository,
      new DeviceReputationProvider(repository, config),
      new IpReputationProvider(repository, config),
      new Ja4hDriftProvider(repository, new TypedEvents(new EventEmitter2())),
      new RequestFrequencyProvider(repository, config),
      new TrustDecayProvider(repository, config),
      new BehaviorAnomalyProvider(repository, config),
    );
    pool = new Pool({ connectionString: url, max: 3 });
  });

  afterAll(async () => {
    await repository.onModuleDestroy();
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM trust_activity WHERE user_id LIKE $1`, [`${uidPrefix}%`]);
    await pool.query(`DELETE FROM trust_signals WHERE user_id LIKE $1`, [`${uidPrefix}%`]);
  });

  const ctx = (id: string): TrustContext => ({
    userId: `${uidPrefix}${id}`,
    deviceId: 'dev-1',
    ip: '192.168.1.1',
    ja4h: 'ja4h-record-test',
    requestTimestamp: new Date(),
  });

  it('evaluateScore does not insert trust_activity rows', async () => {
    const before = await repository.countAllTrustActivity();
    const score = await service.evaluateScore(ctx('eval-only'));
    expect(typeof score).toBe('number');
    const after = await repository.countAllTrustActivity();
    expect(after).toBe(before);
  });

  it('recordTrustContextAfterAllow appends trust_activity and upserts trust_signals', async () => {
    const c = ctx('allow-1');
    await service.recordTrustContextAfterAllow(c, 0.42);
    const { rows: act } = await pool.query(
      `SELECT decision, score FROM trust_activity WHERE user_id = $1`,
      [c.userId],
    );
    expect(act.length).toBe(1);
    expect(act[0].decision).toBe('ALLOW');
    expect(Number(act[0].score)).toBe(0.42);

    const row = await repository.getSignalRow(c.userId, c.deviceId, c.ip);
    expect(row).not.toBeNull();
    expect(row.allow_count).toBe(1);
  });

  it('rejects NaN finalScore for recordTrustContextAfterAllow', async () => {
    await expect(service.recordTrustContextAfterAllow(ctx('nan'), NaN)).rejects.toThrow(/number/);
  });
});
