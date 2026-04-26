import { PolicyMetrics } from '../policy-metrics';

describe('PolicyMetrics', () => {
  it('constructs twice without prom-client global-registry collision (Pitfall 6)', () => {
    const m1 = new PolicyMetrics();
    const m2 = new PolicyMetrics();
    expect(m1).toBeDefined();
    expect(m2).toBeDefined();
    expect(m1.registry).not.toBe(m2.registry);
  });

  it('decisions counter increments by label and is exported by registry', async () => {
    const m = new PolicyMetrics();
    m.decisions.inc({ decision: 'allow' });
    m.decisions.inc({ decision: 'deny' });
    m.decisions.inc({ decision: 'deny' });
    const text = await m.registry.metrics();
    expect(text).toContain('zt_gateway_policy_decisions_total{decision="allow"} 1');
    expect(text).toContain('zt_gateway_policy_decisions_total{decision="deny"} 2');
  });

  it('errors counter increments without labels', async () => {
    const m = new PolicyMetrics();
    m.errors.inc();
    const text = await m.registry.metrics();
    expect(text).toContain('zt_gateway_policy_errors_total 1');
  });

  it('setThreatLevel sets exactly one level gauge to 1 and others to 0', async () => {
    const m = new PolicyMetrics();
    m.setThreatLevel('elevated');
    const text = await m.registry.metrics();
    expect(text).toContain('zt_gateway_threat_level{level="normal"} 0');
    expect(text).toContain('zt_gateway_threat_level{level="elevated"} 1');
    expect(text).toContain('zt_gateway_threat_level{level="critical"} 0');
  });

  it('transitions counter records from->to label combinations', async () => {
    const m = new PolicyMetrics();
    m.transitions.inc({ from: 'normal', to: 'elevated' });
    const text = await m.registry.metrics();
    expect(text).toMatch(/zt_gateway_threat_transitions_total\{from="normal",to="elevated"\} 1/);
  });
});
