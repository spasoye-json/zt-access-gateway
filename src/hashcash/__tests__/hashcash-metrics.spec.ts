/**
 * Phase 5 Wave 0 stubs — HCSH-07 (Counter + Histogram, per-instance Registry).
 * Filled in by 05-04-PLAN.md.
 */
describe('HashcashMetrics', () => {
  describe('counter', () => {
    it.todo('total{outcome="issued",difficulty="18"} increments by 1');
    it.todo('total{outcome="solved",difficulty="22"} increments by 1');
    it.todo('total{outcome="failed",difficulty="20"} increments by 1');
    it.todo('two HashcashMetrics instances do NOT collide on the global prom-client registry (private Registry per instance)');
  });

  describe('histogram', () => {
    it.todo('solveSeconds.observe(t) records into the [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10] buckets');
  });
});
