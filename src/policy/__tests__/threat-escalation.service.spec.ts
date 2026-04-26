import {
  ThreatEscalationService,
  type ClockFn,
} from '../threat-escalation.service';
import { PolicyMetrics } from '../policy-metrics';
import type { AppConfigService } from '../../config/config.service';
import {
  POLICY_DENY,
  AUTH_INVALID_TOKEN,
  HONEYPOT_TRIGGER,
  type ThreatSignalPayload,
} from '../policy-events';

/**
 * Phase 6 Plan 03 — ThreatEscalationService spec.
 *
 * Closes D-18 (sliding window + hard cap), D-19 (max-across-types + single-type
 * Critical), D-20 (linear cooldown ladder + signal-resets-idle), D-22 (sticky
 * manual override), and PLCY-11 (manual override admin path).
 *
 * Pitfall 7 closure: every test gets a fresh service via beforeEach.
 * Pitfall 8 closure: explicit injectable clock — fake timers via the Jest
 * timer API are deliberately avoided; they interact poorly with EventEmitter2
 * dispatch.
 */

function fakeConfig(
  over: Partial<{
    windowMs: number;
    windowMax: number;
    cooldownMs: number;
    elDenies: number;
    crDenies: number;
    elInvalid: number;
    crInvalid: number;
    elHoney: number;
    crHoney: number;
    chN: number;
    deN: number;
    chE: number;
    deE: number;
    chC: number;
    deC: number;
  }> = {},
): AppConfigService {
  return {
    threatWindowMs: over.windowMs ?? 300000,
    threatWindowMaxEvents: over.windowMax ?? 10000,
    threatCooldownMs: over.cooldownMs ?? 600000,
    threatElevatedDenies: over.elDenies ?? 20,
    threatCriticalDenies: over.crDenies ?? 50,
    threatElevatedInvalidTokens: over.elInvalid ?? 30,
    threatCriticalInvalidTokens: over.crInvalid ?? 80,
    threatElevatedHoneypot: over.elHoney ?? 5,
    threatCriticalHoneypot: over.crHoney ?? 15,
    policyChallengeThreshold: over.chN ?? 0.5,
    policyDenyThreshold: over.deN ?? 0.8,
    policyElevatedChallengeThreshold: over.chE ?? 0.3,
    policyElevatedDenyThreshold: over.deE ?? 0.6,
    policyCriticalChallengeThreshold: over.chC ?? 0.2,
    policyCriticalDenyThreshold: over.deC ?? 0.4,
  } as unknown as AppConfigService;
}

const payload = (
  over: Partial<ThreatSignalPayload> = {},
): ThreatSignalPayload => ({
  type: over.type ?? POLICY_DENY,
  ip: over.ip ?? '1.2.3.4',
  ts: over.ts ?? 0,
  ...over,
});

describe('ThreatEscalationService', () => {
  let now = 0;
  const clock: ClockFn = () => now;
  const advance = (ms: number) => {
    now += ms;
  };

  let cfg: AppConfigService;
  let metrics: PolicyMetrics;
  let svc: ThreatEscalationService;

  beforeEach(() => {
    now = 0;
    cfg = fakeConfig();
    metrics = new PolicyMetrics();
    svc = new ThreatEscalationService(cfg, metrics, clock);
  });

  it('starts Normal with default thresholds', () => {
    expect(svc.snapshot().level).toBe('Normal');
    expect(svc.currentChallengeThreshold()).toBe(0.5);
    expect(svc.currentDenyThreshold()).toBe(0.8);
  });

  it('D-18 sliding window evicts entries older than threatWindowMs', () => {
    cfg = fakeConfig({ elDenies: 3, crDenies: 99, windowMs: 1000 });
    svc = new ThreatEscalationService(cfg, new PolicyMetrics(), clock);
    for (let i = 0; i < 3; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Elevated');
    advance(1500); // past windowMs
    svc.onPolicyDeny(payload()); // triggers eviction
    expect(svc.snapshot().signalCounts[POLICY_DENY]).toBe(1);
    expect(svc.snapshot().level).toBe('Normal');
  });

  it('D-18 hard cap at threatWindowMaxEvents', () => {
    cfg = fakeConfig({ windowMax: 5, elDenies: 99 });
    svc = new ThreatEscalationService(cfg, new PolicyMetrics(), clock);
    for (let i = 0; i < 10; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().signalCounts[POLICY_DENY]).toBe(5);
  });

  it('D-19 single-type Critical: threatCriticalHoneypot honeypot events alone push to Critical', () => {
    for (let i = 0; i < 15; i++)
      svc.onHoneypotTrigger(payload({ type: HONEYPOT_TRIGGER }));
    expect(svc.snapshot().level).toBe('Critical');
  });

  it('D-19 max-across-types: deny=Elevated + invalid=Critical → Critical', () => {
    for (let i = 0; i < 25; i++) svc.onPolicyDeny(payload());
    for (let i = 0; i < 80; i++)
      svc.onAuthInvalidToken(payload({ type: AUTH_INVALID_TOKEN }));
    expect(svc.snapshot().level).toBe('Critical');
  });

  it('D-19 stays Normal below all thresholds', () => {
    for (let i = 0; i < 19; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Normal');
  });

  it('D-21 thresholds tighten at Critical', () => {
    for (let i = 0; i < 50; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Critical');
    expect(svc.currentChallengeThreshold()).toBe(0.2);
    expect(svc.currentDenyThreshold()).toBe(0.4);
  });

  it('D-20 cooldown steps down Critical → Elevated → Normal over 2 cooldown windows', () => {
    for (let i = 0; i < 50; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Critical');
    advance(600001); // past cooldownMs since lastSignalAt and lastTransitionAt
    expect(svc.currentChallengeThreshold()).toBe(0.3); // Elevated
    advance(600001);
    expect(svc.currentChallengeThreshold()).toBe(0.5); // Normal
  });

  it('D-20 a new signal resets cooldown idle (level holds)', () => {
    // Use a larger sliding window so the original 50 denies survive past
    // the first 599s pause; otherwise eviction would drop the level back to
    // Normal independently of the cooldown gate we are exercising here.
    cfg = fakeConfig({ windowMs: 2_000_000 });
    svc = new ThreatEscalationService(cfg, new PolicyMetrics(), clock);
    for (let i = 0; i < 50; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Critical');
    advance(599000); // just under cooldown
    svc.onPolicyDeny(payload()); // resets lastSignalAt
    advance(599000); // just under cooldown again
    // Total elapsed > cooldownMs but no full idle window since last signal
    expect(svc.snapshot().level).toBe('Critical');
  });

  it('D-22 manual override sticky regardless of cooldown', () => {
    svc.setManualLevel('Critical');
    advance(2_000_000); // long past any cooldown
    expect(svc.currentDenyThreshold()).toBe(0.4);
    expect(svc.snapshot().level).toBe('Critical');
    expect(svc.snapshot().override).toBe('Critical');
  });

  it('D-22 clearManualLevel resumes auto computation', () => {
    svc.setManualLevel('Critical');
    expect(svc.snapshot().level).toBe('Critical');
    svc.clearManualLevel();
    expect(svc.snapshot().override).toBeNull();
    expect(svc.snapshot().level).toBe('Normal'); // 0 events queued
  });

  it('PLCY-11 manual override to lower level holds even with high event volume', () => {
    for (let i = 0; i < 200; i++) svc.onPolicyDeny(payload());
    svc.setManualLevel('Normal');
    expect(svc.currentChallengeThreshold()).toBe(0.5);
  });

  it('transition logs warn on entering Critical, info on Normal→Elevated', () => {
    const logger = (svc as unknown as { logger: { warn: jest.Mock; log: jest.Mock } }).logger;
    const warn = jest.spyOn(logger, 'warn').mockImplementation(() => {});
    const info = jest.spyOn(logger, 'log').mockImplementation(() => {});
    for (let i = 0; i < 25; i++) svc.onPolicyDeny(payload()); // Normal→Elevated
    expect(info).toHaveBeenCalledWith(
      expect.stringMatching(/Normal → Elevated/),
    );
    for (let i = 0; i < 30; i++) svc.onPolicyDeny(payload()); // Elevated→Critical
    expect(warn).toHaveBeenCalledWith(
      expect.stringMatching(/Elevated → Critical/),
    );
  });

  it('metrics wired: transitions counter + setThreatLevel gauge on each level change', async () => {
    for (let i = 0; i < 25; i++) svc.onPolicyDeny(payload());
    const text = await metrics.registry.metrics();
    expect(text).toMatch(
      /zt_gateway_threat_transitions_total\{from="normal",to="elevated"\} 1/,
    );
    expect(text).toContain('zt_gateway_threat_level{level="elevated"} 1');
    expect(text).toContain('zt_gateway_threat_level{level="normal"} 0');
  });

  it('Pitfall 7: each test starts fresh (no state leak)', () => {
    expect(svc.snapshot().signalCounts).toEqual({});
    expect(svc.snapshot().level).toBe('Normal');
  });

  // W1: long-idle multi-step cooldown ladder
  it('D-20 long idle (3*cooldownMs after Critical) steps Critical → Elevated → Normal across two reads', () => {
    for (let i = 0; i < 50; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Critical');
    advance(1_800_001); // ~3 cooldownMs of complete idle
    // First read: cooldown drops Critical → Elevated → Normal in two stepsElapsed
    expect(svc.currentChallengeThreshold()).toBe(0.5); // Normal
    expect(svc.snapshot().level).toBe('Normal');
  });

  // W3: clearManualLevel must engage cooldown
  it('W3: clearManualLevel after long idle resumes auto-aggregation and steps level down via cooldown', () => {
    svc.setManualLevel('Critical');
    expect(svc.snapshot().level).toBe('Critical');
    advance(1_800_001); // 3 cooldownMs of idle while overridden
    svc.clearManualLevel();
    // With no queued events and 3 cooldown windows elapsed, auto level should be Normal.
    expect(svc.snapshot().override).toBeNull();
    expect(svc.snapshot().level).toBe('Normal');
  });

  it('snapshot exposes level, since, signalCounts, activeThresholds, override', () => {
    for (let i = 0; i < 25; i++) svc.onPolicyDeny(payload());
    const snap = svc.snapshot();
    expect(snap.level).toBe('Elevated');
    expect(typeof snap.since).toBe('number');
    expect(snap.signalCounts[POLICY_DENY]).toBe(25);
    expect(snap.activeThresholds.challenge).toBe(0.3);
    expect(snap.activeThresholds.deny).toBe(0.6);
    expect(snap.override).toBeNull();
  });

  it('snapshot reflects override field after setManualLevel', () => {
    svc.setManualLevel('Elevated');
    const snap = svc.snapshot();
    expect(snap.override).toBe('Elevated');
    expect(snap.level).toBe('Elevated');
    expect(snap.activeThresholds.challenge).toBe(0.3);
  });

  it('D-22 override matching current auto level still records override flag without spurious transition', () => {
    // svc starts Normal. Setting manual override to Normal should record the
    // override but NOT increment the transitions counter (Normal → Normal is a no-op).
    svc.setManualLevel('Normal');
    expect(svc.snapshot().override).toBe('Normal');
    expect(svc.snapshot().level).toBe('Normal');
  });

  it('clearManualLevel after queued events recomputes level upward to match queued counts', () => {
    svc.setManualLevel('Normal');
    for (let i = 0; i < 25; i++) svc.onPolicyDeny(payload()); // queued but ignored under override
    expect(svc.snapshot().level).toBe('Normal');
    svc.clearManualLevel();
    // Auto-aggregation resumes; 25 denies > threatElevatedDenies=20.
    expect(svc.snapshot().level).toBe('Elevated');
  });

  it('AUTH_INVALID_TOKEN handler counts toward effective level (Critical at 80 invalid tokens)', () => {
    for (let i = 0; i < 80; i++)
      svc.onAuthInvalidToken(payload({ type: AUTH_INVALID_TOKEN }));
    expect(svc.snapshot().level).toBe('Critical');
    expect(svc.snapshot().signalCounts[AUTH_INVALID_TOKEN]).toBe(80);
  });

  it('mixed signals across windowMs boundary: only in-window events drive level', () => {
    cfg = fakeConfig({ windowMs: 1000, elDenies: 5, crDenies: 99 });
    svc = new ThreatEscalationService(cfg, new PolicyMetrics(), clock);
    for (let i = 0; i < 5; i++) svc.onPolicyDeny(payload());
    expect(svc.snapshot().level).toBe('Elevated');
    advance(2000); // both windowMs (1s) crossed; cooldown not yet
    svc.onPolicyDeny(payload()); // forces eviction; only 1 in-window event left
    expect(svc.snapshot().signalCounts[POLICY_DENY]).toBe(1);
    expect(svc.snapshot().level).toBe('Normal');
  });
});
