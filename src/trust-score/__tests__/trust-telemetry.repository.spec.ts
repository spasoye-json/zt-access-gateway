import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';
import { Pool } from 'pg';
import {
  beginSuiteTransaction,
  rollbackToSavepoint,
  savepoint,
} from '../../../tests/db-transaction';

function ztTestUrlFromEnv(): string {
  const raw = process.env.DATABASE_URL;
  const u = new URL(raw!);
  u.pathname = '/zt_test';
  return u.href;
}

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('TrustTelemetryRepository', () => {
  const uidPrefix = 'tt-spec-';
  let pool: Pool;
  let repository: TrustTelemetryRepository;

  beforeAll(() => {
    const databaseUrl = ztTestUrlFromEnv();
    pool = new Pool({ connectionString: databaseUrl, max: 5 });
    repository = new TrustTelemetryRepository({ databaseUrl } as unknown as AppConfigService);
  });

  afterAll(async () => {
    await repository.onModuleDestroy();
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM trust_signals WHERE user_id LIKE $1`, [`${uidPrefix}%`]);
  });

  it('getSignalRow returns null when no row exists', async () => {
    const row = await repository.getSignalRow(`${uidPrefix}missing`, 'dev', '127.0.0.1');
    expect(row).toBeNull();
  });

  it('getSignalRow and countAllowsForUserDeviceIp read committed rows', async () => {
    const uid = `${uidPrefix}count-1`;
    const did = 'device-1';
    const ip = '10.0.0.1';
    await pool.query(
      `INSERT INTO trust_signals (user_id, device_id, ip, allow_count)
       VALUES ($1, $2, $3, 4)`,
      [uid, did, ip],
    );
    const row = await repository.getSignalRow(uid, did, ip);
    expect(row).not.toBeNull();
    expect(row!.allow_count).toBe(4);
    const n = await repository.countAllowsForUserDeviceIp(uid, did, ip);
    expect(n).toBe(4);
  });

  it('SAVEPOINT rollback drops inserted trust_signals row (isolation)', async () => {
    const uid = `${uidPrefix}sp-1`;
    const did = 'device-sp';
    const ip = '10.0.0.2';
    const client = await pool.connect();
    const spName = 'trust_telemetry_isolation_sp';
    try {
      await beginSuiteTransaction(client);
      await savepoint(client, spName);
      await client.query(
        `INSERT INTO trust_signals (user_id, device_id, ip, allow_count)
         VALUES ($1, $2, $3, 1)`,
        [uid, did, ip],
      );
      const before = await client.query(
        `SELECT count(*)::int AS c FROM trust_signals WHERE user_id = $1 AND device_id = $2 AND ip = $3`,
        [uid, did, ip],
      );
      expect(before.rows[0].c).toBe(1);
      await rollbackToSavepoint(client, spName);
      const after = await client.query(
        `SELECT count(*)::int AS c FROM trust_signals WHERE user_id = $1 AND device_id = $2 AND ip = $3`,
        [uid, did, ip],
      );
      expect(after.rows[0].c).toBe(0);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });
});
