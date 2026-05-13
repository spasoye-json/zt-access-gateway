import type { Pool } from 'pg';
import { AuditRepository } from '../audit.repository';
import { DbService } from '../../db/db.service';
import type { ServerConfig } from '../../config/slices';

function ztTestUrlFromEnv(): string {
  const raw = process.env.DATABASE_URL;
  const u = new URL(raw);
  u.pathname = '/zt_test';
  return u.href;
}

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('AuditRepository (DB)', () => {
  let dbService: DbService;
  let pool: Pool;
  let repo: AuditRepository;

  beforeAll(() => {
    const databaseUrl = ztTestUrlFromEnv();
    dbService = new DbService({ databaseUrl, dbPoolMax: 5 } as unknown as ServerConfig);
    pool = dbService.unsafePool();
    repo = new AuditRepository(dbService);
  });

  afterAll(async () => {
    await dbService.onModuleDestroy();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM audit_logs WHERE user_id LIKE $1`, ['audit-spec-%']);
  });

  it('insert() persists all 9 fields + auto created_at (AUDT-02)', async () => {
    await repo.insert({
      userId: 'audit-spec-1',
      resource: '/api/users/42',
      action: 'GET',
      decision: 'allow',
      trustScore: 0.123,
      ja4hFingerprint: 'ja4h-abc',
      ipAddress: '10.0.0.1',
      userAgent: 'jest',
      requestId: 'req-1',
    });
    const r = await pool.query(
      `SELECT user_id, resource, action, decision, trust_score::text AS trust_score,
              ja4h_fingerprint, ip_address, user_agent, request_id, created_at
       FROM audit_logs WHERE user_id = $1`,
      ['audit-spec-1'],
    );
    expect(r.rowCount).toBe(1);
    const row = r.rows[0];
    expect(row.resource).toBe('/api/users/42');
    expect(row.action).toBe('GET');
    expect(row.decision).toBe('allow');
    expect(Number(row.trust_score)).toBeCloseTo(0.123);
    expect(row.ja4h_fingerprint).toBe('ja4h-abc');
    expect(row.ip_address).toBe('10.0.0.1');
    expect(row.user_agent).toBe('jest');
    expect(row.request_id).toBe('req-1');
    expect(row.created_at).toBeInstanceOf(Date);
  });

  it('insert() persists null trust_score when undefined (AUDT-02)', async () => {
    await repo.insert({
      userId: 'audit-spec-2',
      resource: '/x',
      action: 'POST',
      decision: 'deny',
    });
    const r = await pool.query(
      `SELECT trust_score, ja4h_fingerprint, ip_address, event_type FROM audit_logs WHERE user_id = $1`,
      ['audit-spec-2'],
    );
    expect(r.rows[0].trust_score).toBeNull();
    expect(r.rows[0].ja4h_fingerprint).toBeNull();
    expect(r.rows[0].ip_address).toBeNull();
    expect(r.rows[0].event_type).toBeNull();
  });

  it('insert() persists eventType into event_type column (AUDT-06)', async () => {
    await repo.insert({
      userId: 'audit-spec-honey',
      resource: '/wp-login.php',
      action: 'GET',
      decision: 'deny',
      eventType: 'HONEYPOT_TRIGGERED',
    });
    const r = await pool.query(`SELECT event_type FROM audit_logs WHERE user_id = $1`, [
      'audit-spec-honey',
    ]);
    expect(r.rowCount).toBe(1);
    expect(r.rows[0].event_type).toBe('HONEYPOT_TRIGGERED');
  });

  it('insert() rejects decision values outside CHECK constraint (AUDT-02)', async () => {
    await expect(
      repo.insert({
        userId: 'audit-spec-3',
        resource: '/x',
        action: 'GET',
        decision: 'bogus' as 'allow',
      }),
    ).rejects.toThrow();
  });

  it('findLogs() returns items ORDER BY created_at DESC + total count (AUDT-05)', async () => {
    await repo.insert({
      userId: 'audit-spec-list-a',
      resource: '/a',
      action: 'GET',
      decision: 'allow',
    });
    await repo.insert({
      userId: 'audit-spec-list-a',
      resource: '/b',
      action: 'GET',
      decision: 'allow',
    });
    await repo.insert({
      userId: 'audit-spec-list-b',
      resource: '/c',
      action: 'POST',
      decision: 'deny',
    });

    const all = await repo.findLogs({ limit: 50, offset: 0 });
    const names = all.items
      .filter((i) => i.userId.startsWith('audit-spec-list-'))
      .map((i) => i.resource);
    // /b inserted after /a, /c after /b → DESC: /c, /b, /a
    expect(names).toEqual(['/c', '/b', '/a']);
    expect(all.total).toBeGreaterThanOrEqual(3);
  });

  it('findLogs() filters by userId (AUDT-05)', async () => {
    await repo.insert({
      userId: 'audit-spec-filter-1',
      resource: '/a',
      action: 'GET',
      decision: 'allow',
    });
    await repo.insert({
      userId: 'audit-spec-filter-2',
      resource: '/b',
      action: 'GET',
      decision: 'allow',
    });

    const r = await repo.findLogs({ userId: 'audit-spec-filter-1', limit: 50, offset: 0 });
    expect(r.items.every((i) => i.userId === 'audit-spec-filter-1')).toBe(true);
    expect(r.total).toBe(1);
  });

  it('findLogs() filters by decision (AUDT-05)', async () => {
    await repo.insert({
      userId: 'audit-spec-dec-1',
      resource: '/a',
      action: 'GET',
      decision: 'allow',
    });
    await repo.insert({
      userId: 'audit-spec-dec-1',
      resource: '/b',
      action: 'GET',
      decision: 'deny',
    });

    const r = await repo.findLogs({
      userId: 'audit-spec-dec-1',
      decision: 'deny',
      limit: 50,
      offset: 0,
    });
    expect(r.items.length).toBe(1);
    expect(r.items[0].decision).toBe('deny');
  });

  it('findLogs() honors limit + offset (AUDT-05)', async () => {
    for (let i = 0; i < 5; i++) {
      await repo.insert({
        userId: 'audit-spec-page',
        resource: `/r${i}`,
        action: 'GET',
        decision: 'allow',
      });
    }
    const page1 = await repo.findLogs({ userId: 'audit-spec-page', limit: 2, offset: 0 });
    const page2 = await repo.findLogs({ userId: 'audit-spec-page', limit: 2, offset: 2 });
    expect(page1.items.length).toBe(2);
    expect(page2.items.length).toBe(2);
    expect(page1.items[0].resource).not.toBe(page2.items[0].resource);
    expect(page1.total).toBe(5);
  });
});
