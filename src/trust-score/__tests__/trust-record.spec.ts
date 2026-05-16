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
import { SIGNAL_RULES } from '../signal-rules';
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

describeDb('TRST-09 trust persistence boundary', () => {
  const uidPrefix = 'tr-record-';
  let dbService: DbService;
  let pool: Pool;
  let repository: TrustTelemetryRepository;
  let service: TrustScoreService;
  let fingerprintStore: FingerprintStore;

  beforeAll(() => {
    const url = ztTestUrlFromEnv();
    const config = mockConfig(url);
    fingerprintStore = new FingerprintStore(new TypedEvents(new EventEmitter2()));
    dbService = new DbService(config);
    pool = dbService.unsafePool();
    repository = new TrustTelemetryRepository(dbService);
    service = new TrustScoreService(
      fingerprintStore,
      repository,
      config,
      SIGNAL_RULES,
      new Ja4hDriftProvider(repository, new TypedEvents(new EventEmitter2())),
      new TrustDecayProvider(repository, config),
      new BehaviorAnomalyProvider(repository, config),
    );
  });

  afterAll(async () => {
    await dbService.onModuleDestroy();
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
