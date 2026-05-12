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

export interface FingerprintBlacklistSizeChangedPayload {
  size: number;
}
