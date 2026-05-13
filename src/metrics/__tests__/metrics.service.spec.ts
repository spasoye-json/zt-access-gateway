import { MetricsService } from '../metrics.service';
import { SecurityMetricsService } from '../../honeypot/security-metrics.service';
import { HashcashMetrics } from '../../hashcash/hashcash-metrics';
import { PolicyMetrics } from '../../policy/policy-metrics';

function makeService(): MetricsService {
  return new MetricsService(
    new SecurityMetricsService(),
    new HashcashMetrics(),
    new PolicyMetrics(),
  );
}

describe('MetricsService', () => {
  describe('own private Registry — cross-cutting metrics', () => {
    it('zt_gateway_requests_total counter increments per decision (MTRC-01)', async () => {
      const m = makeService();
      m.incrementRequest('allow');
      m.incrementRequest('allow');
      m.incrementRequest('deny');
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_requests_total{decision="allow"} 2');
      expect(text).toContain('zt_gateway_requests_total{decision="deny"} 1');
    });

    it('zt_gateway_stage_duration_seconds histogram accepts arbitrary stage strings (Phase D — STAGE_LABELS union removed)', async () => {
      const m = makeService();
      // Stage ids now live on each PipelineStage adapter (src/gateway/pipeline/stages/*.stage.ts).
      // The metrics service no longer pins a TS union; instead it validates the
      // label shape with a regex (lowercase + underscore only).
      for (const id of ['public_bypass', 'mfa_promotion', 'audit_allow', 'record_trust_context']) {
        expect(() => m.observeStageDuration(id, 0.001)).not.toThrow();
      }
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('stage="public_bypass"');
      expect(text).toContain('stage="mfa_promotion"');
    });

    it('stage_duration_seconds buckets are [0.001..1] per D-09', async () => {
      const m = makeService();
      m.observeStageDuration('auth', 0.04);
      const text = await m.getAggregatedMetrics();
      // Prometheus exposition includes le="0.05" bucket line when value 0.04 falls in.
      expect(text).toMatch(/zt_gateway_stage_duration_seconds_bucket\{[^}]*le="0\.05"[^}]*\} \d+/);
      expect(text).toContain('le="0.001"');
      expect(text).toContain('le="1"');
    });

    it('observeStageDuration records under correct stage label (MTRC-02)', async () => {
      const m = makeService();
      m.observeStageDuration('proxy', 0.5);
      const text = await m.getAggregatedMetrics();
      expect(text).toMatch(/zt_gateway_stage_duration_seconds_count\{stage="proxy"\} 1/);
    });

    it('zt_gateway_token_revocations_total counter present (MTRC-04)', async () => {
      const m = makeService();
      m.incrementTokenRevocation();
      m.incrementTokenRevocation();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_token_revocations_total 2');
    });

    it('zt_gateway_ja4h_blacklist_size gauge reflects setJa4hBlacklistSize (MTRC-05)', async () => {
      const m = makeService();
      m.setJa4hBlacklistSize(42);
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_ja4h_blacklist_size 42');
    });

    it('zt_gateway_fingerprint_drift_total counter increments (MTRC-05)', async () => {
      const m = makeService();
      m.incrementFingerprintDrift();
      m.incrementFingerprintDrift();
      m.incrementFingerprintDrift();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_fingerprint_drift_total 3');
    });

    it('zt_gateway_audit_wal_duration_seconds histogram present (D-10)', async () => {
      const m = makeService();
      m.observeAuditWalDuration(0.075);
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_audit_wal_duration_seconds_count 1');
    });

    it('zt_gateway_audit_failures_total counter increments (D-10)', async () => {
      const m = makeService();
      m.incrementAuditFailure();
      m.incrementAuditFailure();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_audit_failures_total 2');
    });
  });

  describe('getAggregatedMetrics() — Registry.merge() across all 4 registries (MTRC-03, MTRC-04, D-01)', () => {
    it('includes honeypot metric in merged output', async () => {
      const sec = new SecurityMetricsService();
      sec.incrementHoneypotTriggers();
      const m = new MetricsService(sec, new HashcashMetrics(), new PolicyMetrics());
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_honeypot_triggers_total 1');
    });

    it('includes hashcash metric in merged output', async () => {
      const hash = new HashcashMetrics();
      hash.total.inc({ outcome: 'issued', difficulty: '18' });
      const m = new MetricsService(new SecurityMetricsService(), hash, new PolicyMetrics());
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_hashcash_total{outcome="issued",difficulty="18"} 1');
    });

    it('includes policy metric in merged output', async () => {
      const pol = new PolicyMetrics();
      pol.decisions.inc({ decision: 'allow' });
      const m = new MetricsService(new SecurityMetricsService(), new HashcashMetrics(), pol);
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_policy_decisions_total{decision="allow"} 1');
    });

    it('includes own-registry metric in merged output', async () => {
      const m = makeService();
      m.incrementRequest('allow');
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_requests_total{decision="allow"} 1');
    });

    it('reflects post-init mutations on subsequent merges (no stale snapshot)', async () => {
      const m = makeService();
      const before = await m.getAggregatedMetrics();
      expect(before).not.toContain('zt_gateway_requests_total{decision="challenge"} 1');
      m.incrementRequest('challenge');
      const after = await m.getAggregatedMetrics();
      expect(after).toContain('zt_gateway_requests_total{decision="challenge"} 1');
    });
  });

  describe('@OnEvent audit.record_failed subscriber (D-05)', () => {
    it('onAuditRecordFailed() increments zt_gateway_audit_failures_total', async () => {
      const m = makeService();
      // Direct method call simulates EventEmitter2 dispatch.
      m.onAuditRecordFailed();
      m.onAuditRecordFailed();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_audit_failures_total 2');
    });
  });

  describe('isolation (Pitfall 2 echo)', () => {
    it('two MetricsService instances do not collide on prom-client global registry', () => {
      expect(() => {
        const a = makeService();
        const b = makeService();
        a.incrementRequest('allow');
        b.incrementRequest('allow');
      }).not.toThrow();
    });
  });

  describe('Phase D — observeStageDuration regex guard + label widening', () => {
    it('mfa_promotions counter lives on the same private registry as zt_gateway_requests_total', async () => {
      const m = makeService();
      m.incrementRequest('allow');
      m.incrementMfaPromotion('allow');
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_requests_total{decision="allow"} 1');
      expect(text).toContain('zt_gateway_mfa_promotions_total{result="allow"} 1');
    });

    it("incrementMfaPromotion('allow') and ('reject') exposes correct labelled counters", async () => {
      const m = makeService();
      m.incrementMfaPromotion('allow');
      m.incrementMfaPromotion('reject');
      m.incrementMfaPromotion('reject');
      const text = await m.getAggregatedMetrics();
      expect(text).toMatch(/zt_gateway_mfa_promotions_total\{result="allow"\} 1/);
      expect(text).toMatch(/zt_gateway_mfa_promotions_total\{result="reject"\} 2/);
    });

    it('observeStageDuration accepts all 13 Phase D stage ids', async () => {
      const m = makeService();
      const ids = [
        'public_bypass',
        'honeypot_bypass',
        'auth',
        'revocation',
        'auth_only',
        'trust_score',
        'hashcash',
        'policy',
        'mfa_promotion',
        'audit_allow',
        'proxy',
        'bopla_strip',
        'record_trust_context',
      ];
      for (const id of ids) {
        m.observeStageDuration(id, 0.001);
      }
      const text = await m.getAggregatedMetrics();
      for (const id of ids) {
        expect(text).toMatch(
          new RegExp(`zt_gateway_stage_duration_seconds_count\\{stage="${id}"\\} 1`),
        );
      }
    });

    it('observeStageDuration drops labels that do not match /^[a-z_]+$/', async () => {
      const m = makeService();
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      try {
        m.observeStageDuration('camelCase', 0.001);
        m.observeStageDuration('with-dash', 0.001);
        m.observeStageDuration('UPPER', 0.001);
        m.observeStageDuration('with space', 0.001);
        const text = await m.getAggregatedMetrics();
        expect(text).not.toContain('stage="camelCase"');
        expect(text).not.toContain('stage="with-dash"');
        expect(text).not.toContain('stage="UPPER"');
        expect(warn).toHaveBeenCalled();
      } finally {
        warn.mockRestore();
      }
    });
  });

  describe('Phase 14 Plan 01 — orphan seam @OnEvent wiring (SC-1, D-01..D-03)', () => {
    it('onFingerprintBlacklistSizeChanged drives setJa4hBlacklistSize gauge', async () => {
      const m = makeService();
      m.onFingerprintBlacklistSizeChanged({ size: 7 });
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_ja4h_blacklist_size 7');
    });

    it('onFingerprintDriftDetected increments fingerprint drift counter', async () => {
      const m = makeService();
      m.onFingerprintDriftDetected();
      m.onFingerprintDriftDetected();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_fingerprint_drift_total 2');
    });

    it('onAuthTokenRevoked increments token revocation counter', async () => {
      const m = makeService();
      m.onAuthTokenRevoked();
      const text = await m.getAggregatedMetrics();
      expect(text).toContain('zt_gateway_token_revocations_total 1');
    });
  });
});
