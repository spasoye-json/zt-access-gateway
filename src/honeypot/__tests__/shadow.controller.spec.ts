import 'reflect-metadata';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TypedEvents } from '../../shared/typed-events';
import { ShadowController } from '../shadow.controller';
import { FingerprintStore } from '../../fingerprint/fingerprint.store';
import { SecurityMetricsService } from '../security-metrics.service';
import type { AuditService } from '../../audit/audit.service';
import type { DemoModeService } from '../../shared/demo-mode/demo-mode.service';
import type { ServerConfig } from '../../config/slices';
import { HONEYPOT_KEY } from '../honeypot.decorator';
import { HONEYPOT_TRIGGER } from '../../policy/policy-events';

// Mock sleep/randomDelay so tests don't wait 2-5 seconds
jest.mock('../../shared/sleep.util', () => ({
  sleep: jest.fn().mockResolvedValue(undefined),
  randomDelay: jest.fn().mockReturnValue(100),
}));

import { sleep, randomDelay } from '../../shared/sleep.util';

function makeMockReq(path: string, ja4h = 'abc123') {
  return {
    method: 'GET',
    ip: '1.2.3.4',
    headers: { 'user-agent': 'scanner/1.0' },
    'x-ja4h': ja4h,
    path,
  } as any;
}

function makeMockRes() {
  const res: any = {
    _contentType: '',
    _status: 0,
    _body: undefined,
  };
  res.type = jest.fn().mockReturnValue(res);
  res.status = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

describe('ShadowController', () => {
  let controller: ShadowController;
  let store: jest.Mocked<FingerprintStore>;
  let metrics: jest.Mocked<SecurityMetricsService>;
  let config: jest.Mocked<ServerConfig>;
  let events: TypedEvents;
  let audit: jest.Mocked<AuditService>;
  let demoMode: jest.Mocked<DemoModeService>;
  let emitSpy: jest.SpyInstance;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    store = {
      add: jest.fn(),
      isBlacklisted: jest.fn(),
      isTerminal: jest.fn(),
      size: jest.fn(),
      clear: jest.fn(),
    } as any;

    metrics = {
      incrementHoneypotTriggers: jest.fn(),
      getMetrics: jest.fn(),
    } as any;

    config = {
      blacklistTtlMs: 3600000,
    } as any;

    events = new TypedEvents(new EventEmitter2());
    emitSpy = jest.spyOn(events, 'emit');

    audit = {
      log: jest.fn().mockResolvedValue(undefined),
    } as any;
    demoMode = {
      isActive: jest.fn().mockReturnValue(false),
    } as any;

    controller = new ShadowController(store, metrics, config, events, audit, demoMode);
    warnSpy = jest.spyOn(console, 'warn').mockImplementation();

    (sleep as jest.Mock).mockClear();
    (randomDelay as jest.Mock).mockClear();
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  const routes: Array<{
    method: string;
    path: string;
    assertion: (res: any) => void;
  }> = [
    {
      method: 'wpLogin',
      path: '/wp-login.php',
      assertion: (res) => {
        expect(res.type).toHaveBeenCalledWith('text/html');
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('<form'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('wp-login'));
      },
    },
    {
      method: 'adminConfig',
      path: '/admin/config.json',
      assertion: (res) => {
        expect(res.json).toHaveBeenCalledWith(expect.any(Object));
      },
    },
    {
      method: 'dotEnv',
      path: '/.env',
      assertion: (res) => {
        expect(res.type).toHaveBeenCalledWith('text/plain');
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('DB_PASSWORD='));
      },
    },
    {
      method: 'apiDebug',
      path: '/api/v1/debug',
      assertion: (res) => {
        expect(res.json).toHaveBeenCalledWith(expect.any(Object));
      },
    },
    {
      method: 'graphqlIntrospection',
      path: '/graphql/introspection',
      assertion: (res) => {
        expect(res.json).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.objectContaining({
              __schema: expect.any(Object),
            }),
          }),
        );
      },
    },
    {
      method: 'actuatorHealth',
      path: '/actuator/health',
      assertion: (res) => {
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ status: 'UP' }));
      },
    },
    {
      method: 'internalKeys',
      path: '/api/v1/internal/keys',
      assertion: (res) => {
        expect(res.json).toHaveBeenCalledWith(expect.any(Array));
      },
    },
  ];

  routes.forEach(({ method, path, assertion }) => {
    describe(`${method} (${path})`, () => {
      it('calls store.add() with JA4H fingerprint, ttlMs, and isTerminal: true', async () => {
        const req = makeMockReq(path);
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(store.add).toHaveBeenCalledWith('abc123', {
          ttlMs: 3600000,
          isTerminal: true,
        });
      });

      it('calls metrics.incrementHoneypotTriggers()', async () => {
        const req = makeMockReq(path);
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(metrics.incrementHoneypotTriggers).toHaveBeenCalledTimes(1);
      });

      it('calls console.warn with HONEYPOT_TRIGGERED structured log', async () => {
        const req = makeMockReq(path);
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('HONEYPOT_TRIGGERED'));
      });

      it('calls sleep() for tarpit delay', async () => {
        const req = makeMockReq(path);
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(sleep).toHaveBeenCalledTimes(1);
      });

      it('returns expected response content', async () => {
        const req = makeMockReq(path);
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        assertion(res);
      });

      it('uses "unknown" as fingerprint when x-ja4h is absent', async () => {
        const req = makeMockReq(path, undefined);
        delete req['x-ja4h'];
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(store.add).toHaveBeenCalledWith('unknown', expect.any(Object));
      });

      it('emits HONEYPOT_TRIGGER with ip + ja4h + resource (Phase 6 D-14)', async () => {
        const req = makeMockReq(path, 'jh-fp-xyz');
        req.ip = '5.6.7.8';
        const res = makeMockRes();
        await (controller as any)[method](req, res);
        expect(emitSpy).toHaveBeenCalledWith(
          HONEYPOT_TRIGGER,
          expect.objectContaining({
            type: HONEYPOT_TRIGGER,
            ip: '5.6.7.8',
            ja4h: 'jh-fp-xyz',
            resource: path,
          }),
        );
      });
    });
  });

  describe('honeypot.trigger emission edge cases (Phase 6 D-14)', () => {
    it('emits with ja4h: undefined when x-ja4h is absent', async () => {
      const req = makeMockReq('/wp-login.php');
      delete req['x-ja4h'];
      const res = makeMockRes();
      await (controller as any).wpLogin(req, res);
      expect(emitSpy).toHaveBeenCalledWith(
        HONEYPOT_TRIGGER,
        expect.objectContaining({
          type: HONEYPOT_TRIGGER,
          ja4h: undefined,
        }),
      );
    });

    it('payload always contains type, ip, ts (ThreatSignalPayload shape)', async () => {
      const req = makeMockReq('/.env');
      const res = makeMockRes();
      await (controller as any).dotEnv(req, res);
      const calls = emitSpy.mock.calls.filter((c) => c[0] === HONEYPOT_TRIGGER);
      expect(calls.length).toBe(1);
      expect(calls[0][1]).toEqual(
        expect.objectContaining({
          type: HONEYPOT_TRIGGER,
          ip: '1.2.3.4',
          ts: expect.any(Number),
        }),
      );
    });
  });

  describe('audit row on honeypot hit (Slice C, #4)', () => {
    it('writes one audit row with decision=deny + eventType=HONEYPOT_TRIGGERED before responding', async () => {
      const req = makeMockReq('/.env', 'jh-fp-1');
      const res = makeMockRes();
      await (controller as any).dotEnv(req, res);
      expect(audit.log).toHaveBeenCalledTimes(1);
      const entry = audit.log.mock.calls[0][0];
      expect(entry).toEqual(
        expect.objectContaining({
          decision: 'deny',
          eventType: 'HONEYPOT_TRIGGERED',
          resource: '/.env',
          ja4hFingerprint: 'jh-fp-1',
          userId: 'anonymous',
        }),
      );
    });

    it('audit.log is invoked before sleep/tarpit (write-then-tarpit ordering)', async () => {
      const calls: string[] = [];
      audit.log.mockImplementation(async () => {
        calls.push('audit');
      });
      (sleep as jest.Mock).mockImplementation(async () => {
        calls.push('sleep');
      });
      const req = makeMockReq('/.env');
      const res = makeMockRes();
      await (controller as any).dotEnv(req, res);
      expect(calls).toEqual(['audit', 'sleep']);
    });
  });

  describe('demo-mode tarpit cap (Slice C, #4)', () => {
    it('caps random delay at 50ms when DemoModeService.isActive() is true', async () => {
      (demoMode.isActive as jest.Mock).mockReturnValue(true);
      const req = makeMockReq('/.env');
      const res = makeMockRes();
      await (controller as any).dotEnv(req, res);
      expect(randomDelay).toHaveBeenCalledTimes(1);
      const [, max] = (randomDelay as jest.Mock).mock.calls[0];
      expect(max).toBeLessThanOrEqual(50);
    });

    it('uses production 2000-5000ms range when demo mode is inactive', async () => {
      (demoMode.isActive as jest.Mock).mockReturnValue(false);
      const req = makeMockReq('/.env');
      const res = makeMockRes();
      await (controller as any).dotEnv(req, res);
      expect(randomDelay).toHaveBeenCalledWith(2000, 5000);
    });
  });

  describe('@Honeypot() decorator metadata', () => {
    it('wpLogin has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.wpLogin)).toBe(true);
    });

    it('adminConfig has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.adminConfig)).toBe(true);
    });

    it('dotEnv has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.dotEnv)).toBe(true);
    });

    it('apiDebug has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.apiDebug)).toBe(true);
    });

    it('graphqlIntrospection has HONEYPOT_KEY metadata set to true', () => {
      expect(
        Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.graphqlIntrospection),
      ).toBe(true);
    });

    it('actuatorHealth has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.actuatorHealth)).toBe(
        true,
      );
    });

    it('internalKeys has HONEYPOT_KEY metadata set to true', () => {
      expect(Reflect.getMetadata(HONEYPOT_KEY, ShadowController.prototype.internalKeys)).toBe(true);
    });
  });
});
