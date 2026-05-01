/**
 * Phase 6 — Threat-signal bus event names + payload contract (D-13, D-14, D-15).
 *
 * Phase 6 publishes: POLICY_DENY (PolicyEvaluator), AUTH_INVALID_TOKEN (JwtAuthGuard
 * patch), HONEYPOT_TRIGGER (ShadowController patch).
 *
 * Phase 7 will emit MFA_FAILED. Phase 9 may emit AUDIT_SIGNAL.
 * ThreatEscalationService subscribes to all five from day one — missing emitters are silent.
 */

export const POLICY_DENY = 'policy.deny';
export const AUTH_INVALID_TOKEN = 'auth.invalid_token';
export const HONEYPOT_TRIGGER = 'honeypot.trigger';
export const MFA_FAILED = 'mfa.failed';
export const MFA_RATE_LIMITED = 'mfa.rate_limited';
export const AUDIT_SIGNAL = 'audit.signal';

/**
 * D-15: common payload schema. `type` echoes the event name for routing convenience.
 * Forensic fields (resource, action) are optional and only attached by emitters that have them.
 */
export interface ThreatSignalPayload {
  type: string;
  ip: string;
  userId?: string;
  ja4h?: string;
  ts: number;
  resource?: string;
  action?: string;
}

export type SignalType =
  | typeof POLICY_DENY
  | typeof AUTH_INVALID_TOKEN
  | typeof HONEYPOT_TRIGGER
  | typeof MFA_FAILED
  | typeof MFA_RATE_LIMITED
  | typeof AUDIT_SIGNAL;
