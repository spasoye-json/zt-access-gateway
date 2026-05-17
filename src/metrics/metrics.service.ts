import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { Counter, Gauge, Histogram, Registry } from 'prom-client';
import { SecurityMetricsService } from '../honeypot/security-metrics.service';
import { HashcashMetrics } from '../hashcash/hashcash-metrics';
import { PolicyMetrics } from '../policy/policy-metrics';
import {
  AUTH_TOKEN_REVOKED,
  FINGERPRINT_BLACKLIST_SIZE_CHANGED,
  FINGERPRINT_DRIFT_DETECTED,
  TRUST_PROVIDER_FAULT,
  type FingerprintBlacklistSizeChangedPayload,
  type TrustProviderFaultPayload,
} from './metrics-events';

/** Buckets for both stage_duration_seconds and audit_wal_duration_seconds (D-09, D-10). */
const DURATION_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1] as const;

/**
 * Phase D — pipeline stage labels are no longer a TS union. They are owned
 * by each PipelineStage's `id` field (src/gateway/pipeline/stages/*.stage.ts).
 * Authoritative current set (13 stages):
 *   public_bypass, honeypot_bypass, auth, revocation, auth_only,
 *   trust_score, hashcash, policy, mfa_promotion, audit_allow, proxy,
 *   bopla_strip, record_trust_context
 *
 * `observeStageDuration` runtime-guards the label with /^[a-z_]+$/ so a typo
 * in a future stage.id cannot pollute the histogram with camelCase labels.
 */
const STAGE_ID_PATTERN = /^[a-z_]+$/;

/**
 * Phase 9 — MetricsService (MTRC-01..05, D-01..D-03, D-09, D-10).
 *
 * Owns a private prom-client Registry for cross-cutting gateway metrics
 * (Pitfall 2: never use the prom-client global registry — Jest collisions).
 *
 * On every /metrics scrape, calls Registry.merge() across all 4 registries
 * so a single text/plain response contains every metric in the gateway:
 *   - SecurityMetricsService (honeypot triggers)
 *   - HashcashMetrics (PoW counters + solve histogram)
 *   - PolicyMetrics (decisions, errors, threat level, transitions)
 *   - this.registry (cross-cutting requests, stages, blacklist, drift, audit WAL)
 *
 * Note (D-03, D-05): zt_gateway_audit_wal_duration_seconds and zt_gateway_audit_failures_total
 * live HERE, not in AuditModule, to avoid a circular dependency (AuditModule does not
 * import MetricsModule). Phase 10 GatewayMiddleware calls observeAuditWalDuration()
 * around its writeBlocking() invocation and incrementAuditFailure() for writeBlocking
 * exhaustion. For best-effort record() failures, AuditService emits 'audit.record_failed'
 * via EventEmitter2; this service subscribes via @OnEvent and increments the counter.
 */
@Injectable()
export class MetricsService {
  private readonly registry = new Registry();

  // ── Cross-cutting gateway counters (D-02) ──

  private readonly requestsTotal = new Counter({
    name: 'zt_gateway_requests_total',
    help: 'Total gateway requests by final decision',
    labelNames: ['decision'] as const, // values: allow | challenge | deny
    registers: [this.registry],
  });

  private readonly tokenRevocations = new Counter({
    name: 'zt_gateway_token_revocations_total',
    help: 'Total token revocations recorded by AuthController',
    registers: [this.registry],
  });

  private readonly ja4hBlacklistSize = new Gauge({
    name: 'zt_gateway_ja4h_blacklist_size',
    help: 'Current size of the JA4H fingerprint blacklist',
    registers: [this.registry],
  });

  private readonly fingerprintDriftTotal = new Counter({
    name: 'zt_gateway_fingerprint_drift_total',
    help: 'Total mid-session JA4H fingerprint drift detections',
    registers: [this.registry],
  });

  /**
   * Issue #13 — TrustScoreService.faultAdjustment emits TRUST_PROVIDER_FAULT
   * when a signal rule or provider rejects (catching the error and adding a
   * 0.1 bias). Six concurrent faults compound to a +0.6 swing → score clamps
   * to 1.0. This counter makes that swing observable per offender.
   */
  private readonly trustProviderFaultTotal = new Counter({
    name: 'zt_gateway_trust_provider_fault_total',
    help: 'Total trust-signal provider/rule faults caught by TrustScoreService',
    labelNames: ['provider'] as const,
    registers: [this.registry],
  });

  // ── Pipeline stage latency (D-09) ──

  private readonly stageDuration = new Histogram({
    name: 'zt_gateway_stage_duration_seconds',
    help: 'Duration of each pipeline stage in seconds',
    labelNames: ['stage'] as const,
    buckets: [...DURATION_BUCKETS],
    registers: [this.registry],
  });

  // ── Audit WAL metrics (D-03, D-10) — live here to avoid AuditModule ↔ MetricsModule cycle ──

  private readonly auditWalDuration = new Histogram({
    name: 'zt_gateway_audit_wal_duration_seconds',
    help: 'Total time for an audit WAL write including all retries',
    buckets: [...DURATION_BUCKETS],
    registers: [this.registry],
  });

  private readonly auditFailuresTotal = new Counter({
    name: 'zt_gateway_audit_failures_total',
    help: 'Audit write failures (WAL exhaustion + best-effort record() catches)',
    registers: [this.registry],
  });

  // ── MFA promotion outcomes (D-08) ──

  private readonly mfaPromotions = new Counter({
    name: 'zt_gateway_mfa_promotions_total',
    help: 'MFA promotion outcomes on CHALLENGE decisions',
    labelNames: ['result'] as const, // values: allow | reject
    registers: [this.registry],
  });

  constructor(
    private readonly securityMetrics: SecurityMetricsService,
    private readonly hashcashMetrics: HashcashMetrics,
    private readonly policyMetrics: PolicyMetrics,
  ) {}

  // ── Seam methods called by Phase 10 GatewayMiddleware ──

  incrementRequest(decision: 'allow' | 'challenge' | 'deny'): void {
    this.requestsTotal.inc({ decision });
  }

  /**
   * Records a pipeline stage duration. `stage` is the PipelineStage.id from
   * the registered stage adapter. Labels that don't match /^[a-z_]+$/ are
   * dropped + logged once, so a typo cannot pollute the histogram with
   * unbounded high-cardinality labels.
   */
  observeStageDuration(stage: string, durationSeconds: number): void {
    if (!STAGE_ID_PATTERN.test(stage)) {
      console.warn(`metrics: dropped stage_duration sample with invalid label "${stage}"`);
      return;
    }
    this.stageDuration.observe({ stage }, durationSeconds);
  }

  observeAuditWalDuration(durationSeconds: number): void {
    this.auditWalDuration.observe(durationSeconds);
  }

  incrementAuditFailure(): void {
    this.auditFailuresTotal.inc();
  }

  /**
   * D-08 — Increment MFA promotion outcome counter.
   * Called by GatewayMiddleware when a CHALLENGE decision is resolved (allow)
   * or rejected (reject) via X-MFA-Token validation.
   */
  incrementMfaPromotion(result: 'allow' | 'reject'): void {
    this.mfaPromotions.inc({ result });
  }

  incrementTokenRevocation(): void {
    this.tokenRevocations.inc();
  }

  setJa4hBlacklistSize(n: number): void {
    this.ja4hBlacklistSize.set(n);
  }

  incrementFingerprintDrift(): void {
    this.fingerprintDriftTotal.inc();
  }

  // ── Event subscribers (D-05 seam from AuditService.record() failures) ──

  /**
   * D-05 — AuditService.record() emits 'audit.record_failed' when a best-effort
   * insert catches an error. This subscriber increments the counter without
   * AuditModule needing to import MetricsModule (D-03 — circular dep prevention).
   * EventEmitter2 is provided by EventEmitterModule (Phase 6 D-13).
   */
  @OnEvent('audit.record_failed')
  onAuditRecordFailed(): void {
    this.auditFailuresTotal.inc();
  }

  // ── Phase 14 Plan 01 — orphan seam @OnEvent wiring (SC-1, D-01..D-03) ──

  /**
   * D-01 — FingerprintStore emits FINGERPRINT_BLACKLIST_SIZE_CHANGED after every
   * mutation (add/clear/lazy-evict). MetricsModule cannot import FingerprintModule
   * (circular via HoneypotModule), so EventEmitter2 is the seam.
   */
  @OnEvent(FINGERPRINT_BLACKLIST_SIZE_CHANGED)
  onFingerprintBlacklistSizeChanged(p: FingerprintBlacklistSizeChangedPayload): void {
    this.setJa4hBlacklistSize(p.size);
  }

  /**
   * D-02 — Ja4hDriftProvider emits FINGERPRINT_DRIFT_DETECTED in the drift branch
   * (row.ja4h !== ctx.ja4h). Drift detection physically lives in the provider,
   * not Ja4hMiddleware (which runs before auth and has no prior-fingerprint state).
   */
  @OnEvent(FINGERPRINT_DRIFT_DETECTED)
  onFingerprintDriftDetected(): void {
    this.incrementFingerprintDrift();
  }

  /**
   * SC-1 — AuthController.revoke emits AUTH_TOKEN_REVOKED after a successful
   * revocationService.revoke() call (not on 403 ownership failure).
   */
  @OnEvent(AUTH_TOKEN_REVOKED)
  onAuthTokenRevoked(): void {
    this.incrementTokenRevocation();
  }

  /**
   * Issue #13 — emitted from TrustScoreService.faultAdjustment with the
   * offending rule/provider name (e.g. `device_reputation`, `ja4h_drift`).
   */
  @OnEvent(TRUST_PROVIDER_FAULT)
  onTrustProviderFault(p: TrustProviderFaultPayload): void {
    this.trustProviderFaultTotal.inc({ provider: p.provider });
  }

  // ── Aggregation surface (MTRC-03) ──

  /**
   * Returns Prometheus text-format metrics merged across all 4 registries.
   * Calls Registry.merge() per invocation — metric objects are by reference
   * so this is O(1) in metric count and always reflects current state.
   */
  async getAggregatedMetrics(): Promise<string> {
    const merged = Registry.merge([
      this.securityMetrics.getRegistry(),
      this.hashcashMetrics.registry,
      this.policyMetrics.registry,
      this.registry,
    ]);
    return merged.metrics();
  }
}
