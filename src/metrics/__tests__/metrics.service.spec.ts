/**
 * Phase 9 Wave 0 RED stubs for MetricsService. Implementation lands in Plan 09-02.
 * Covers MTRC-01, MTRC-02, MTRC-04, MTRC-05.
 */
describe('MetricsService', () => {
  describe('own private Registry — cross-cutting metrics (D-02, D-03)', () => {
    it.todo('zt_gateway_requests_total{decision} counter increments per decision label (MTRC-01)');
    it.todo('zt_gateway_stage_duration_seconds histogram has 8 stage labels: ja4h, blacklist, auth, revocation, trust_score, hashcash, policy, proxy (MTRC-02)');
    it.todo('zt_gateway_stage_duration_seconds buckets are [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1] (MTRC-02)');
    it.todo('zt_gateway_token_revocations_total counter present (MTRC-04)');
    it.todo('zt_gateway_ja4h_blacklist_size gauge present (MTRC-05)');
    it.todo('zt_gateway_fingerprint_drift_total counter present (MTRC-05)');
    it.todo('zt_gateway_audit_wal_duration_seconds histogram present (D-10)');
    it.todo('zt_gateway_audit_failures_total counter present (D-10)');
    it.todo("@OnEvent('audit.record_failed') subscriber increments zt_gateway_audit_failures_total (D-05)");
  });

  describe('getAggregatedMetrics() — Registry.merge() (MTRC-04, D-01)', () => {
    it.todo('merges SecurityMetricsService.getRegistry() into output');
    it.todo('merges HashcashMetrics.registry into output');
    it.todo('merges PolicyMetrics.registry into output');
    it.todo('merges own private registry into output');
    it.todo('returns text/plain Prometheus exposition format');
    it.todo('calls Registry.merge() per invocation (no cached snapshot)');
  });

  describe('observeStageDuration(stage, durationSeconds) seam (MTRC-02)', () => {
    it.todo('records into zt_gateway_stage_duration_seconds with stage label');
  });

  describe('observeAuditWalDuration(durationSeconds) seam (D-10)', () => {
    it.todo('records into zt_gateway_audit_wal_duration_seconds');
  });

  describe('incrementAuditFailure() seam (D-03)', () => {
    it.todo('increments zt_gateway_audit_failures_total — used by Phase 10 catch site');
  });

  describe('two MetricsService instances do not collide (Pitfall 2 echo)', () => {
    it.todo('constructing two instances does not throw "metric already registered"');
  });
});
