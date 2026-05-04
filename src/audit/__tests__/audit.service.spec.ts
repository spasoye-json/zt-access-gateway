import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuditService } from '../audit.service';
import { AuditExhaustedException } from '../audit-exhausted.exception';
import type { AuditRepository } from '../audit.repository';
import type { AppConfigService } from '../../config/config.service';

jest.mock('../../shared/sleep.util', () => ({
  sleep: jest.fn().mockResolvedValue(undefined),
}));
import { sleep } from '../../shared/sleep.util';

function makeRepo(): jest.Mocked<AuditRepository> {
  return {
    insert: jest.fn(),
    findLogs: jest.fn(),
    onModuleDestroy: jest.fn(),
  } as unknown as jest.Mocked<AuditRepository>;
}

function makeConfig(maxRetries = 3, baseDelay = 50): AppConfigService {
  return { auditWalMaxRetries: maxRetries, auditWalBaseDelayMs: baseDelay } as unknown as AppConfigService;
}

function makeEmitter(): EventEmitter2 {
  const e = new EventEmitter2();
  jest.spyOn(e, 'emit');
  return e;
}

describe('AuditService', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    (sleep as jest.Mock).mockClear();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe('writeBlocking() — WAL retry path (AUDT-03, AUDT-04)', () => {
    it('inserts on first attempt — no retries', async () => {
      const repo = makeRepo();
      repo.insert.mockResolvedValueOnce(undefined);
      const svc = new AuditService(makeConfig(), repo, makeEmitter());

      await svc.writeBlocking({ userId: 'u', resource: '/x', action: 'GET', decision: 'allow' });

      expect(repo.insert).toHaveBeenCalledTimes(1);
      expect(sleep).not.toHaveBeenCalled();
    });

    it('retries with 50ms→100ms→200ms backoff and succeeds before exhaustion', async () => {
      const repo = makeRepo();
      repo.insert
        .mockRejectedValueOnce(new Error('db1'))
        .mockRejectedValueOnce(new Error('db2'))
        .mockResolvedValueOnce(undefined);
      const svc = new AuditService(makeConfig(3, 50), repo, makeEmitter());

      await svc.writeBlocking({ userId: 'u', resource: '/x', action: 'GET', decision: 'allow' });

      expect(repo.insert).toHaveBeenCalledTimes(3);
      // Two sleeps (between 3 attempts). Defaults: 50ms, 100ms.
      expect((sleep as jest.Mock).mock.calls).toEqual([[50], [100]]);
    });

    it('throws AuditExhaustedException after 3 failed attempts (AUDT-04)', async () => {
      const repo = makeRepo();
      repo.insert.mockRejectedValue(new Error('db down'));
      const svc = new AuditService(makeConfig(3, 50), repo, makeEmitter());

      await expect(
        svc.writeBlocking({ userId: 'u', resource: '/x', action: 'GET', decision: 'allow' }),
      ).rejects.toBeInstanceOf(AuditExhaustedException);

      expect(repo.insert).toHaveBeenCalledTimes(3);
      // Only 2 sleeps (after attempts 0 and 1; not after final attempt).
      expect((sleep as jest.Mock).mock.calls).toEqual([[50], [100]]);
    });

    it('respects auditWalMaxRetries from config', async () => {
      const repo = makeRepo();
      repo.insert.mockRejectedValue(new Error('db down'));
      const svc = new AuditService(makeConfig(5, 50), repo, makeEmitter());

      await expect(svc.writeBlocking({ userId: 'u', resource: '/x', action: 'GET', decision: 'allow' })).rejects.toBeInstanceOf(AuditExhaustedException);
      expect(repo.insert).toHaveBeenCalledTimes(5);
    });

    it('AuditExhaustedException carries name="AuditExhaustedException" for instanceof-free callers', async () => {
      const repo = makeRepo();
      repo.insert.mockRejectedValue(new Error('db'));
      const svc = new AuditService(makeConfig(1, 50), repo, makeEmitter());
      try {
        await svc.writeBlocking({ userId: 'u', resource: '/x', action: 'GET', decision: 'allow' });
        fail('expected throw');
      } catch (e) {
        expect((e as Error).name).toBe('AuditExhaustedException');
      }
    });
  });

  describe('record() — best-effort path (AUDT-01, AUDT-06)', () => {
    it('inserts on success', async () => {
      const repo = makeRepo();
      repo.insert.mockResolvedValueOnce(undefined);
      const events = makeEmitter();
      const svc = new AuditService(makeConfig(), repo, events);

      await expect(
        svc.record({ userId: 'u', resource: '/x', action: 'GET', decision: 'challenge' }),
      ).resolves.toBeUndefined();
      expect(events.emit).not.toHaveBeenCalledWith('audit.record_failed');
    });

    it('catches DB errors, logs console.warn, emits audit.record_failed (D-05) — never throws', async () => {
      const repo = makeRepo();
      repo.insert.mockRejectedValueOnce(new Error('db down'));
      const events = makeEmitter();
      const svc = new AuditService(makeConfig(), repo, events);

      await expect(
        svc.record({ userId: 'u', resource: '/x', action: 'GET', decision: 'deny' }),
      ).resolves.toBeUndefined();
      expect(warnSpy).toHaveBeenCalled();
      expect(events.emit).toHaveBeenCalledWith('audit.record_failed');
    });

    it('records HONEYPOT_TRIGGERED entries with eventType (AUDT-06)', async () => {
      const repo = makeRepo();
      repo.insert.mockResolvedValueOnce(undefined);
      const svc = new AuditService(makeConfig(), repo, makeEmitter());

      await svc.record({
        userId: 'scanner',
        resource: '/wp-login.php',
        action: 'GET',
        decision: 'deny',
        eventType: 'HONEYPOT_TRIGGERED',
        ja4hFingerprint: 'ja4h-abc',
        ipAddress: '10.0.0.1',
      });
      expect(repo.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          decision: 'deny',
          resource: '/wp-login.php',
          eventType: 'HONEYPOT_TRIGGERED',
        }),
      );
    });
  });

  describe('queryLogs() (AUDT-05)', () => {
    it('applies default limit 50 / offset 0 when DTO omits them', async () => {
      const repo = makeRepo();
      repo.findLogs.mockResolvedValueOnce({ items: [], total: 0 });
      const svc = new AuditService(makeConfig(), repo, makeEmitter());

      await svc.queryLogs({});
      expect(repo.findLogs).toHaveBeenCalledWith({
        userId: undefined,
        decision: undefined,
        limit: 50,
        offset: 0,
      });
    });

    it('threads filters and pagination through to repository', async () => {
      const repo = makeRepo();
      repo.findLogs.mockResolvedValueOnce({ items: [], total: 0 });
      const svc = new AuditService(makeConfig(), repo, makeEmitter());

      await svc.queryLogs({ userId: 'u', decision: 'deny', limit: 10, offset: 20 });
      expect(repo.findLogs).toHaveBeenCalledWith({
        userId: 'u',
        decision: 'deny',
        limit: 10,
        offset: 20,
      });
    });
  });
});
