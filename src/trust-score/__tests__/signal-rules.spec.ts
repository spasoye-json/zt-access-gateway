import { SIGNAL_RULES, evaluateRule, type SignalRule } from '../signal-rules';
import type { TrustTelemetryRepository } from '../trust-telemetry.repository';
import type { TrustConfig } from '../../config/slices';
import type { TrustContext } from '../trust-context';

const config: TrustConfig = {
  knownThreshold: 3,
  decayHalfLifeMs: 60_000,
  anomalyWarmupN: 10,
  frequencyWindowMs: 60_000,
  frequencyNormalMax: 30,
};

const ctx: TrustContext = {
  userId: 'u1',
  deviceId: 'd1',
  ip: '10.0.0.1',
  ja4h: 'fp',
  requestTimestamp: new Date('2026-05-16T12:00:00Z'),
};

function ruleByName(name: string): SignalRule {
  const r = SIGNAL_RULES.find((x) => x.name === name);
  if (!r) throw new Error(`missing rule: ${name}`);
  return r;
}

describe('SIGNAL_RULES', () => {
  it('contains exactly the three threshold rules', () => {
    expect(SIGNAL_RULES.map((r) => r.name)).toEqual([
      'device_reputation',
      'ip_reputation',
      'request_frequency',
    ]);
  });

  describe('device_reputation', () => {
    const rule = ruleByName('device_reputation');

    it('is decayable', () => {
      expect(rule.decayable).toBe(true);
    });

    it('returns device_known (-0.15) when prior allow count meets knownThreshold', async () => {
      const repo = {
        countAllowsForUserDeviceIp: jest.fn().mockResolvedValue(3),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'device_reputation',
        delta: -0.15,
        reason: 'device_known',
        decayable: true,
      });
      expect(repo.countAllowsForUserDeviceIp).toHaveBeenCalledWith('u1', 'd1', '10.0.0.1');
    });

    it('returns device_unknown (+0.15) when prior allow count is below knownThreshold', async () => {
      const repo = {
        countAllowsForUserDeviceIp: jest.fn().mockResolvedValue(2),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'device_reputation',
        delta: 0.15,
        reason: 'device_unknown',
        decayable: true,
      });
    });
  });

  describe('ip_reputation', () => {
    const rule = ruleByName('ip_reputation');

    it('is decayable', () => {
      expect(rule.decayable).toBe(true);
    });

    it('returns ip_trusted (-0.15) when allow sum meets knownThreshold', async () => {
      const repo = {
        sumAllowsForUserIp: jest.fn().mockResolvedValue(3),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'ip_reputation',
        delta: -0.15,
        reason: 'ip_trusted',
        decayable: true,
      });
      expect(repo.sumAllowsForUserIp).toHaveBeenCalledWith('u1', '10.0.0.1');
    });

    it('returns ip_untrusted (+0.15) when allow sum is below knownThreshold', async () => {
      const repo = {
        sumAllowsForUserIp: jest.fn().mockResolvedValue(2),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'ip_reputation',
        delta: 0.15,
        reason: 'ip_untrusted',
        decayable: true,
      });
    });
  });

  describe('request_frequency', () => {
    const rule = ruleByName('request_frequency');

    it('is NOT decayable (window-bounded; cannot go stale)', () => {
      expect(rule.decayable).toBe(false);
    });

    it('returns frequency_burst (+0.2) when activity count strictly exceeds frequencyNormalMax', async () => {
      const repo = {
        countActivitySince: jest.fn().mockResolvedValue(31),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'request_frequency',
        delta: 0.2,
        reason: 'frequency_burst',
        decayable: false,
      });
      const expectedSince = new Date(ctx.requestTimestamp.getTime() - config.frequencyWindowMs);
      expect(repo.countActivitySince).toHaveBeenCalledWith('u1', expectedSince);
    });

    it('returns frequency_normal (-0.1) when activity count equals frequencyNormalMax (gt, not gte)', async () => {
      const repo = {
        countActivitySince: jest.fn().mockResolvedValue(30),
      } as unknown as TrustTelemetryRepository;
      const adj = await evaluateRule(rule, repo, config, ctx);
      expect(adj).toEqual({
        source: 'request_frequency',
        delta: -0.1,
        reason: 'frequency_normal',
        decayable: false,
      });
    });

    it('falls back to new Date() when ctx.requestTimestamp is absent', async () => {
      const repo = {
        countActivitySince: jest.fn().mockResolvedValue(0),
      } as unknown as TrustTelemetryRepository;
      const { requestTimestamp: _omit, ...ctxNoTs } = ctx;
      const adj = await evaluateRule(rule, repo, config, ctxNoTs);
      expect(adj.reason).toBe('frequency_normal');
      expect(repo.countActivitySince).toHaveBeenCalledTimes(1);
    });
  });
});
