/**
 * Phase 6 — Threat-signal bus event names + payload contract (D-13, D-14, D-15).
 *
 * Phase 6 publishes: POLICY_DENY (PolicyEvaluator), AUTH_INVALID_TOKEN (JwtAuthGuard
 * patch), HONEYPOT_TRIGGER (ShadowController patch).
 *
 * Phase 7 emits MFA_FAILED + MFA_RATE_LIMITED.
 * Phase 11 adds MFA_ENROLLMENT_RESET on admin enrollment reset (CONTEXT specifics).
 * Phase 9 may emit AUDIT_SIGNAL.
 * ThreatEscalationService subscribes to all from day one — missing emitters are silent.
 */

export const POLICY_DENY = 'policy.deny';
export const AUTH_INVALID_TOKEN = 'auth.invalid_token';
export const HONEYPOT_TRIGGER = 'honeypot.trigger';
export const MFA_FAILED = 'mfa.failed';
export const MFA_RATE_LIMITED = 'mfa.rate_limited';
export const MFA_ENROLLMENT_RESET = 'mfa.enrollment_reset';
export const MFA_ENROLLMENT_CONFIRMED = 'mfa.enrollment_confirmed';
/**
 * IN-01 (phase 14, iter3): infra observability event names previously inlined
 * as magic strings at the MfaService.recordInfraError emit site and the
 * verifyTotp decrypt-failure site. Promoted to exported constants so future
 * subscribers (dashboards, ThreatEscalationService.onMfaInfraError) cannot
 * silently typo-mismatch the event name.
 */
export const MFA_INFRA_ERROR = 'mfa.infra_error';
export const MFA_SECRET_DECRYPT_FAILED = 'mfa.secret_decrypt_failed';
export const AUDIT_SIGNAL = 'audit.signal';

/**
 * D-15: common payload schema. `type` echoes the event name for routing convenience.
 * Forensic fields (resource, action) are optional and only attached by emitters that have them.
 *
 * Phase A3 (TypedEvents wrapper, 260513-kwm): `type` and `ip` are optional because
 * the in-process emitters at MFA_INFRA_ERROR / MFA_SECRET_DECRYPT_FAILED /
 * MFA_ENROLLMENT_CONFIRMED / MFA_ENROLLMENT_RESET historically omit them
 * (userId-bound operational events) and the on-disk wire shape must be preserved
 * byte-identically. The extra optional MFA-flavored fields (`op`, `deviceId`,
 * `reason`, `jti`, `deleted`) reflect the same legacy emitters; listeners
 * (ThreatEscalationService etc.) only consume the core ip/userId/ja4h/ts fields,
 * so widening the interface here is non-breaking.
 */
export interface ThreatSignalPayload {
  type?: string;
  ip?: string;
  userId?: string;
  ja4h?: string;
  ts: number;
  resource?: string;
  action?: string;
  // MFA-flavored optional context (see comment above).
  op?: string;
  deviceId?: string;
  reason?: string;
  jti?: string;
  deleted?: boolean;
  // Gateway-flavored: requestId is attached when AUDIT_SIGNAL is emitted from
  // GatewayMiddleware so dashboards can correlate the WAL-exhausted signal back
  // to the failing request trace.
  requestId?: string;
}

export type SignalType =
  | typeof POLICY_DENY
  | typeof AUTH_INVALID_TOKEN
  | typeof HONEYPOT_TRIGGER
  | typeof MFA_FAILED
  | typeof MFA_RATE_LIMITED
  | typeof MFA_ENROLLMENT_RESET
  | typeof MFA_ENROLLMENT_CONFIRMED
  | typeof MFA_INFRA_ERROR
  | typeof MFA_SECRET_DECRYPT_FAILED
  | typeof AUDIT_SIGNAL;
