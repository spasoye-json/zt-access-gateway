import { HashcashMetrics } from '../hashcash-metrics';

describe('HashcashMetrics', () => {
  describe('counter', () => {
    it('total{outcome="issued",difficulty="18"} increments by 1', async () => {
      const m = new HashcashMetrics();
      m.total.inc({ outcome: 'issued', difficulty: '18' });
      const json = await m.registry.getMetricsAsJSON();
      const total = json.find((x) => x.name === 'zt_gateway_hashcash_total');
      expect(total).toBeDefined();
      const sample = total!.values.find(
        (v: { labels: Record<string, string>; value: number }) =>
          v.labels.outcome === 'issued' && v.labels.difficulty === '18',
      );
      expect(sample?.value).toBe(1);
    });

    it('total{outcome="solved",difficulty="22"} increments by 1', async () => {
      const m = new HashcashMetrics();
      m.total.inc({ outcome: 'solved', difficulty: '22' });
      const json = await m.registry.getMetricsAsJSON();
      const sample = json
        .find((x) => x.name === 'zt_gateway_hashcash_total')!
        .values.find(
          (v: { labels: Record<string, string>; value: number }) =>
            v.labels.outcome === 'solved' && v.labels.difficulty === '22',
        );
      expect(sample?.value).toBe(1);
    });

    it('total{outcome="failed",difficulty="20"} increments by 1', async () => {
      const m = new HashcashMetrics();
      m.total.inc({ outcome: 'failed', difficulty: '20' });
      const json = await m.registry.getMetricsAsJSON();
      const sample = json
        .find((x) => x.name === 'zt_gateway_hashcash_total')!
        .values.find(
          (v: { labels: Record<string, string>; value: number }) =>
            v.labels.outcome === 'failed' && v.labels.difficulty === '20',
        );
      expect(sample?.value).toBe(1);
    });

    it('two HashcashMetrics instances do not collide on the global prom-client registry', () => {
      // Pitfall 3 in 05-RESEARCH.md
      expect(() => {
        const a = new HashcashMetrics();
        const b = new HashcashMetrics();
        a.total.inc({ outcome: 'issued', difficulty: '18' });
        b.total.inc({ outcome: 'issued', difficulty: '18' });
      }).not.toThrow();
    });
  });

  describe('histogram', () => {
    it('solveSeconds.observe(t) records into the configured buckets [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]', async () => {
      const m = new HashcashMetrics();
      m.solveSeconds.observe(0.5);
      m.solveSeconds.observe(1.5);
      const json = await m.registry.getMetricsAsJSON();
      const hist = json.find((x) => x.name === 'zt_gateway_hashcash_solve_seconds');
      expect(hist).toBeDefined();
      // bucket boundaries on the Histogram instance
      const buckets = (m.solveSeconds as unknown as { buckets: number[] }).buckets;
      expect(buckets).toEqual([0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10]);
    });
  });
});
