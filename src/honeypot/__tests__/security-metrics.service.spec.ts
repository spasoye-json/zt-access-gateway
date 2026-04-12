import { SecurityMetricsService } from '../security-metrics.service';

describe('SecurityMetricsService', () => {
  let service: SecurityMetricsService;

  beforeEach(() => {
    service = new SecurityMetricsService();
  });

  it('incrementHoneypotTriggers() increments the counter value by 1', async () => {
    service.incrementHoneypotTriggers();
    const metrics = await service.getMetrics();
    expect(metrics).toContain('zt_gateway_honeypot_triggers_total 1');
  });

  it('getMetrics() returns a string containing zt_gateway_honeypot_triggers_total', async () => {
    const metrics = await service.getMetrics();
    expect(typeof metrics).toBe('string');
    expect(metrics).toContain('zt_gateway_honeypot_triggers_total');
  });

  it('counter starts at 0', async () => {
    const metrics = await service.getMetrics();
    expect(metrics).toContain('zt_gateway_honeypot_triggers_total 0');
  });

  it('counter increments across multiple calls', async () => {
    service.incrementHoneypotTriggers();
    service.incrementHoneypotTriggers();
    service.incrementHoneypotTriggers();
    const metrics = await service.getMetrics();
    expect(metrics).toContain('zt_gateway_honeypot_triggers_total 3');
  });
});
