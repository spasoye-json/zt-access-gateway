/**
 * Phase 11 Wave 0 — PendingEnrollmentStore (RED).
 * Tests fail until enrollment.store.ts is implemented in Plan 11-01.
 */
import type { AppConfigService } from '../../config/config.service';
// NOTE: import is type-only here so the spec compiles even before enrollment.store.ts exists.
// The implementation tasks in Plan 11-01 will add the value-level import via dynamic require.

const loadStore = async (): Promise<typeof import('../enrollment.store')> => {
  return await import('../enrollment.store');
};

function buildCfg(ttlMs: number): AppConfigService {
  return { mfaEnrollPendingTtlMs: ttlMs } as unknown as AppConfigService;
}

describe('PendingEnrollmentStore', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-05-03T00:00:00Z'));
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  it('ENROLL-06: set + get returns stored entry within TTL', async () => {
    const { PendingEnrollmentStore } = await loadStore();
    const store = new PendingEnrollmentStore(buildCfg(5_000));
    store.set('eid-1', { userId: 'u1', secret: 'JBSWY3DPEHPK3PXP' });
    const got = store.get('eid-1');
    expect(got).not.toBeNull();
    expect(got!.userId).toBe('u1');
    expect(got!.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(got!.expiresAt).toBe(Date.now() + 5_000);
  });

  it('ENROLL-06: get returns null and lazy-evicts after TTL', async () => {
    const { PendingEnrollmentStore } = await loadStore();
    const store = new PendingEnrollmentStore(buildCfg(1_000));
    store.set('eid-2', { userId: 'u2', secret: 'AAAA' });
    jest.advanceTimersByTime(1_001);
    expect(store.get('eid-2')).toBeNull();
    expect(store.size()).toBe(0); // lazy eviction confirmed via size()
  });

  it('ENROLL-06: delete removes entry', async () => {
    const { PendingEnrollmentStore } = await loadStore();
    const store = new PendingEnrollmentStore(buildCfg(60_000));
    store.set('eid-3', { userId: 'u3', secret: 'BBBB' });
    store.delete('eid-3');
    expect(store.get('eid-3')).toBeNull();
    expect(store.size()).toBe(0);
  });

  it('ENROLL-06: get on unknown id returns null without throwing', async () => {
    const { PendingEnrollmentStore } = await loadStore();
    const store = new PendingEnrollmentStore(buildCfg(60_000));
    expect(store.get('does-not-exist')).toBeNull();
  });

  it.todo('ENROLL-06b: re-set on existing id refreshes expiresAt');
});
