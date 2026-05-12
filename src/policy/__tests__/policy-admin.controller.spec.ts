import { Reflector } from '@nestjs/core';
import { PolicyAdminController } from '../policy-admin.controller';
import { ROLES_KEY } from '../../auth/roles.decorator';
import type { PolicyEvaluatorService } from '../policy-evaluator.service';
import type { ThreatEscalationService } from '../threat-escalation.service';

/**
 * Phase 6 — PolicyAdminController unit spec (D-22, PLCY-06, PLCY-11).
 *
 * Asserts:
 *  - class-level @Roles('admin') metadata (RolesGuard runs as global APP_GUARD — Phase 3)
 *  - delegation to PolicyEvaluatorService.addRule/removeRule (writer mutex lives there — D-02)
 *  - idempotent POST rules (Casbin addPolicy returns false for duplicates — surfaced as { added:false })
 *  - Pitfall 1 propagation (savePolicy returned false → throws → 500 via filter)
 *  - delegation to ThreatEscalationService.snapshot/setManualLevel/clearManualLevel
 *  - controller introduces no concurrency of its own (mutex is upstream)
 *
 * DTO validation tests (empty sub / invalid level → 400) live in Plan 06 (e2e)
 * where the global ValidationPipe is wired.
 */
describe('PolicyAdminController', () => {
  let evaluator: jest.Mocked<PolicyEvaluatorService>;
  let threat: jest.Mocked<ThreatEscalationService>;
  let ctrl: PolicyAdminController;

  beforeEach(() => {
    evaluator = {
      getRules: jest.fn().mockResolvedValue([['role:user', '/users', 'GET']]),
      addRule: jest.fn().mockResolvedValue(true),
      removeRule: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<PolicyEvaluatorService>;
    threat = {
      snapshot: jest.fn().mockReturnValue({
        level: 'Normal',
        since: 0,
        signalCounts: {},
        activeThresholds: { challenge: 0.5, deny: 0.8 },
        override: null,
      }),
      setManualLevel: jest.fn(),
      clearManualLevel: jest.fn(),
    } as unknown as jest.Mocked<ThreatEscalationService>;
    ctrl = new PolicyAdminController(evaluator, threat);
  });

  it('class-level @Roles("admin") metadata present', () => {
    const reflector = new Reflector();
    const meta = reflector.get<string[]>(ROLES_KEY, PolicyAdminController);
    expect(meta).toEqual(['admin']);
  });

  it('GET rules → { rules }', async () => {
    expect(await ctrl.listRules()).toEqual({
      rules: [['role:user', '/users', 'GET']],
    });
    expect(evaluator.getRules).toHaveBeenCalledTimes(1);
  });

  it('POST rules delegates to evaluator.addRule and returns { added: true }', async () => {
    const r = await ctrl.addRule({
      sub: 'role:t',
      obj: '/t',
      act: 'GET',
    });
    expect(evaluator.addRule).toHaveBeenCalledWith('role:t', '/t', 'GET');
    expect(r).toEqual({ added: true });
  });

  it('POST rules is idempotent: duplicate rule returns { added: false } (no 409)', async () => {
    evaluator.addRule.mockResolvedValueOnce(false);
    const r = await ctrl.addRule({
      sub: 'role:dup',
      obj: '/x',
      act: 'GET',
    });
    expect(r).toEqual({ added: false });
  });

  it('POST rules surfaces evaluator errors (Pitfall 1 propagation)', async () => {
    evaluator.addRule.mockRejectedValueOnce(
      new Error('savePolicy returned false — check policy/model.conf has [role_definition]'),
    );
    await expect(ctrl.addRule({ sub: 'r', obj: '/x', act: 'GET' })).rejects.toThrow(
      /savePolicy returned false/,
    );
  });

  it('DELETE rules delegates to evaluator.removeRule and returns { removed: true }', async () => {
    const r = await ctrl.removeRule({
      sub: 'r',
      obj: '/x',
      act: 'GET',
    });
    expect(evaluator.removeRule).toHaveBeenCalledWith('r', '/x', 'GET');
    expect(r).toEqual({ removed: true });
  });

  it('DELETE rules surfaces { removed: false } when rule did not exist', async () => {
    evaluator.removeRule.mockResolvedValueOnce(false);
    const r = await ctrl.removeRule({
      sub: 'role:ghost',
      obj: '/none',
      act: 'GET',
    });
    expect(r).toEqual({ removed: false });
  });

  it('GET escalation returns the snapshot', () => {
    expect(ctrl.getEscalation()).toEqual(
      expect.objectContaining({ level: 'Normal', override: null }),
    );
    expect(threat.snapshot).toHaveBeenCalledTimes(1);
  });

  it('POST escalation invokes setManualLevel and echoes the level (PLCY-11)', () => {
    expect(ctrl.setEscalation({ level: 'Critical' } as never)).toEqual({
      ok: true,
      level: 'Critical',
    });
    expect(threat.setManualLevel).toHaveBeenCalledWith('Critical');
  });

  it('POST escalation accepts each ThreatLevel literal', () => {
    expect(ctrl.setEscalation({ level: 'Normal' } as never).level).toBe('Normal');
    expect(ctrl.setEscalation({ level: 'Elevated' } as never).level).toBe('Elevated');
    expect(ctrl.setEscalation({ level: 'Critical' } as never).level).toBe('Critical');
    expect(threat.setManualLevel).toHaveBeenCalledTimes(3);
  });

  it('DELETE escalation invokes clearManualLevel (PLCY-11)', () => {
    expect(ctrl.clearEscalation()).toEqual({ ok: true });
    expect(threat.clearManualLevel).toHaveBeenCalledTimes(1);
  });

  // Concurrency proof — controller is a thin pass-through; the writer mutex
  // is owned by PolicyEvaluatorService.addRule (verified in 06-02 spec).
  it('controller does not bypass evaluator (mutex enforced upstream)', async () => {
    await Promise.all([
      ctrl.addRule({ sub: 'r1', obj: '/x', act: 'GET' }),
      ctrl.addRule({ sub: 'r2', obj: '/x', act: 'GET' }),
      ctrl.addRule({ sub: 'r3', obj: '/x', act: 'GET' }),
    ]);
    expect(evaluator.addRule).toHaveBeenCalledTimes(3);
  });
});
