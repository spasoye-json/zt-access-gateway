import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Request } from 'express';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TypedEvents } from '../../shared/typed-events';
import { PolicyEvaluatorService } from '../policy-evaluator.service';
import { PolicyMetrics } from '../policy-metrics';
import { POLICY_DENY } from '../policy-events';
import type { PolicyConfig } from '../../config/slices';
import type { TrustScoreService } from '../../trust-score/trust-score.service';
import type { ThreatEscalationService } from '../threat-escalation.service';
import type { UserClaims } from '../../auth/interfaces/user-claims.interface';

/**
 * Phase 6 — PolicyEvaluatorService spec (Task 2 of Plan 06-02).
 *
 * Uses real Casbin enforcer (per Phase 6 testing constraint: real libs from day
 * one). Each test gets a fresh tmp copy of policy/policy.csv so mutator paths
 * never touch the canonical CSV (verification step in 06-02-PLAN.md).
 */

function tmpCsvCopy(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pol-eval-'));
  const dst = path.join(dir, 'policy.csv');
  fs.copyFileSync(path.join(process.cwd(), 'policy/policy.csv'), dst);
  return dst;
}

function fakeConfig(
  overrides: Partial<{ csvPath: string; modelPath: string }> = {},
): PolicyConfig {
  return {
    modelPath: overrides.modelPath ?? path.join(process.cwd(), 'policy/model.conf'),
    csvPath: overrides.csvPath ?? tmpCsvCopy(),
  } as unknown as PolicyConfig;
}

function fakeThreat(
  overrides: { challenge?: number; deny?: number } = {},
): ThreatEscalationService {
  return {
    currentChallengeThreshold: () => overrides.challenge ?? 0.5,
    currentDenyThreshold: () => overrides.deny ?? 0.8,
  } as unknown as ThreatEscalationService;
}

interface FakeReqOverrides {
  path?: string;
  method?: string;
  user?: UserClaims | undefined;
  trustScore?: number;
  ja4h?: string;
  ip?: string;
}

function fakeReq(over: FakeReqOverrides = {}): Request {
  const r = {
    path: over.path ?? '/users',
    method: over.method ?? 'GET',
    user:
      'user' in over
        ? over.user
        : { userId: '42', roles: ['user'], deviceId: 'd1', jti: 'j1', exp: 0 },
    trustScore: over.trustScore,
    headers: {},
    ip: over.ip ?? '1.2.3.4',
    socket: { remoteAddress: '1.2.3.4' },
  } as unknown as Request;
  // Mirror Ja4hMiddleware (src/fingerprint/ja4h.middleware.ts:23) — attach as
  // a top-level property on req, NOT in headers.
  (r as unknown as Record<string, unknown>)['x-ja4h'] = over.ja4h ?? 'jh1';
  return r;
}

describe('PolicyEvaluatorService', () => {
  let svc: PolicyEvaluatorService;
  let metrics: PolicyMetrics;
  let trust: jest.Mocked<TrustScoreService>;
  let events: TypedEvents;
  let emitSpy: jest.SpyInstance;

  beforeEach(async () => {
    metrics = new PolicyMetrics();
    trust = {
      evaluateScore: jest.fn().mockResolvedValue(0.5),
    } as unknown as jest.Mocked<TrustScoreService>;
    events = new TypedEvents(new EventEmitter2());
    emitSpy = jest.spyOn(events, 'emit');
    svc = new PolicyEvaluatorService(fakeConfig(), fakeThreat(), trust, metrics, events);
    await svc.onModuleInit();
  });

  // ── PLCY-01: enforcer constructs from real model + CSV ─────────────────
  it('PLCY-01 onModuleInit loads real Casbin enforcer', async () => {
    const rules = await svc.getRules();
    expect(rules).toEqual(expect.arrayContaining([['role:user', '/users', 'GET']]));
  });

  it('PLCY-01 fails closed at startup with bogus model path', async () => {
    const bad = new PolicyEvaluatorService(
      fakeConfig({ modelPath: '/no/such', csvPath: '/no/such' }),
      fakeThreat(),
      trust,
      metrics,
      events,
    );
    await expect(bad.onModuleInit()).rejects.toBeDefined();
  });

  // ── PLCY-03 ALLOW ──────────────────────────────────────────────────────
  it('PLCY-03 ALLOW: low score + casbinAllow → score_below_challenge_threshold', async () => {
    const r = await svc.evaluate(fakeReq({ trustScore: 0.1 }));
    expect(r).toEqual({
      decision: 'ALLOW',
      reason: 'score_below_challenge_threshold',
      score: 0.1,
      matchedSubject: 'role:user',
    });
    expect(emitSpy).not.toHaveBeenCalledWith(POLICY_DENY, expect.anything());
  });

  // ── PLCY-04 CHALLENGE ──────────────────────────────────────────────────
  it('PLCY-04 CHALLENGE: mid-band score + casbinAllow → score_in_challenge_band', async () => {
    const r = await svc.evaluate(fakeReq({ trustScore: 0.6 }));
    expect(r.decision).toBe('CHALLENGE');
    expect((r as { reason: string }).reason).toBe('score_in_challenge_band');
    expect((r as { matchedSubject?: string }).matchedSubject).toBe('role:user');
    expect(emitSpy).not.toHaveBeenCalledWith(POLICY_DENY, expect.anything());
  });

  // ── PLCY-05 DENY: no matching rule ─────────────────────────────────────
  it('PLCY-05 DENY: casbin_no_match → DENY + emits policy.deny', async () => {
    const r = await svc.evaluate(
      fakeReq({ path: '/admin/secrets', method: 'GET', trustScore: 0.1 }),
    );
    expect(r.decision).toBe('DENY');
    expect((r as { reason: string }).reason).toBe('casbin_no_match');
    expect(emitSpy).toHaveBeenCalledWith(
      POLICY_DENY,
      expect.objectContaining({
        type: POLICY_DENY,
        userId: '42',
        ip: '1.2.3.4',
        ja4h: 'jh1',
        resource: '/admin/secrets',
        action: 'GET',
      }),
    );
  });

  // ── PLCY-05 DENY: high score ───────────────────────────────────────────
  it('PLCY-05 DENY: score_above_deny_threshold even with casbinAllow → emits policy.deny', async () => {
    const r = await svc.evaluate(fakeReq({ trustScore: 0.9 }));
    expect(r.decision).toBe('DENY');
    expect((r as { reason: string }).reason).toBe('score_above_deny_threshold');
    expect(emitSpy).toHaveBeenCalledWith(POLICY_DENY, expect.any(Object));
  });

  // ── D-03 fail-closed runtime ──────────────────────────────────────────
  it('D-03 fail-closed runtime: enforce() throws → DENY policy_error + metrics.errors++ + emits policy.deny', async () => {
    const errCounter = metrics.registry.getSingleMetric('zt_gateway_policy_errors_total');
    const before = await errCounter.get();
    const beforeVal = (before as { values: { value: number }[] }).values[0]?.value ?? 0;

    jest
      .spyOn((svc as unknown as { enforcer: { enforce: jest.Mock } }).enforcer, 'enforce')
      .mockRejectedValueOnce(new Error('boom'));

    const r = await svc.evaluate(fakeReq({ trustScore: 0.1 }));
    expect(r).toEqual(expect.objectContaining({ decision: 'DENY', reason: 'policy_error' }));

    const after = await errCounter.get();
    const afterVal = (after as { values: { value: number }[] }).values[0].value;
    expect(afterVal).toBeGreaterThan(beforeVal);
    expect(emitSpy).toHaveBeenCalledWith(POLICY_DENY, expect.any(Object));
  });

  // ── D-09 score seam: req.trustScore wins ──────────────────────────────
  it('D-09 seam: req.trustScore wins over TrustScoreService.evaluateScore', async () => {
    await svc.evaluate(fakeReq({ trustScore: 0.1 }));
    expect(trust.evaluateScore).not.toHaveBeenCalled();
  });

  it('D-09 seam: falls back to TrustScoreService.evaluateScore when trustScore undefined', async () => {
    trust.evaluateScore.mockResolvedValueOnce(0.1);
    await svc.evaluate(fakeReq({}));
    expect(trust.evaluateScore).toHaveBeenCalledTimes(1);
    expect(trust.evaluateScore).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: '42',
        deviceId: 'd1',
        ip: '1.2.3.4',
        ja4h: 'jh1',
      }),
    );
  });

  // ── D-04 multi-role any-allows ────────────────────────────────────────
  it('D-04 multi-role: matches role:user even when role:guest does not', async () => {
    const r = await svc.evaluate(
      fakeReq({
        user: {
          userId: '42',
          roles: ['guest', 'user'],
          deviceId: 'd1',
          jti: 'j1',
          exp: 0,
        },
        trustScore: 0.1,
      }),
    );
    expect(r).toEqual(
      expect.objectContaining({
        decision: 'ALLOW',
        matchedSubject: 'role:user',
      }),
    );
  });

  // ── D-22 mutex: 5 concurrent addRule calls do not interleave ──────────
  it('D-22 mutex: concurrent addRule calls do not interleave', async () => {
    const order: string[] = [];
    const enforcer = (svc as unknown as { enforcer: import('casbin').Enforcer }).enforcer;
    jest.spyOn(enforcer, 'addPolicy').mockImplementation(async (...args: string[]) => {
      order.push(`start:${args[0]}`);
      await new Promise((res) => setImmediate(res));
      order.push(`end:${args[0]}`);
      return true;
    });
    jest.spyOn(enforcer, 'savePolicy').mockResolvedValue(true);

    await Promise.all([
      svc.addRule('role:t1', '/t', 'GET'),
      svc.addRule('role:t2', '/t', 'GET'),
      svc.addRule('role:t3', '/t', 'GET'),
      svc.addRule('role:t4', '/t', 'GET'),
      svc.addRule('role:t5', '/t', 'GET'),
    ]);

    // Each "start:tN" must be immediately followed by "end:tN" — no interleaving.
    expect(order).toHaveLength(10);
    for (let i = 0; i < order.length; i += 2) {
      expect(order[i].replace('start', 'end')).toBe(order[i + 1]);
    }
  });

  // ── Pitfall 1: savePolicy() returning false → throw ───────────────────
  it('Pitfall 1: addRule throws when savePolicy() returns false', async () => {
    const enforcer = (svc as unknown as { enforcer: import('casbin').Enforcer }).enforcer;
    jest.spyOn(enforcer, 'savePolicy').mockResolvedValueOnce(false);
    await expect(svc.addRule('role:x', '/x', 'GET')).rejects.toThrow(
      /savePolicy returned false.*\[role_definition\]/,
    );
  });

  it('Pitfall 1: removeRule throws when savePolicy() returns false', async () => {
    const enforcer = (svc as unknown as { enforcer: import('casbin').Enforcer }).enforcer;
    // First add a rule so removePolicy returns true and we hit the savePolicy
    // branch.
    jest.spyOn(enforcer, 'savePolicy').mockResolvedValueOnce(true);
    await svc.addRule('role:rmtest', '/rm', 'GET');
    jest.spyOn(enforcer, 'savePolicy').mockResolvedValueOnce(false);
    await expect(svc.removeRule('role:rmtest', '/rm', 'GET')).rejects.toThrow(
      /savePolicy returned false.*\[role_definition\]/,
    );
  });

  // ── Defensive: missing user (JwtAuthGuard precondition) ───────────────
  it('returns DENY no_user when req.user is undefined', async () => {
    const r = await svc.evaluate(fakeReq({ user: undefined }));
    expect(r).toEqual(expect.objectContaining({ decision: 'DENY', reason: 'no_user' }));
  });
});
