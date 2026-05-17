/**
 * Phase 14 Plan 01 (D-03) — event names for the orphan MetricsService seams.
 *
 * Cross-module wiring uses EventEmitter2 instead of direct injection because
 * MetricsModule transitively imports FingerprintModule (via HoneypotModule)
 * and AuthModule (via PolicyModule), so reverse direct injection creates a
 * DI cycle. Matches the existing `audit.record_failed` seam at
 * metrics.service.ts:163.
 */
export const FINGERPRINT_BLACKLIST_SIZE_CHANGED = 'fingerprint.blacklist_size_changed';
export const FINGERPRINT_DRIFT_DETECTED = 'fingerprint.drift_detected';
export const AUTH_TOKEN_REVOKED = 'auth.token_revoked';
/**
 * Phase A3 (TypedEvents wrapper): promoted from inlined magic string at
 * audit.service.ts:78 and metrics.service.ts:169 so the typed-events registry
 * can declare its payload shape (void — emitted with no payload arg).
 */
export const AUDIT_RECORD_FAILED = 'audit.record_failed';

/**
 * Issue #13 — emitted by TrustScoreService.faultAdjustment when a signal
 * rule or provider rejects. Provider name is the rule/provider source so
 * the swing is observable per offender on the dashboard.
 */
export const TRUST_PROVIDER_FAULT = 'trust.provider_fault';

export interface FingerprintBlacklistSizeChangedPayload {
  size: number;
}

export interface TrustProviderFaultPayload {
  provider: string;
}
