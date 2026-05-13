import type { ConfigService } from '@nestjs/config';

/**
 * Policy + Threat Escalation slice (Phase 6 D-19, D-20, D-23).
 *
 * Trust thresholds and threat-escalation counts per level (NORMAL/ELEVATED/CRITICAL).
 * Joi cross-field validator enforces Critical < Elevated < Normal at boot.
 */
export interface PolicyConfig {
  /** Path to Casbin model.conf (FileAdapter). Default 'policy/model.conf'. */
  readonly modelPath: string;
  /** Path to Casbin policy.csv (FileAdapter). Default 'policy/policy.csv'. */
  readonly csvPath: string;
  /** Trust score above which policy returns CHALLENGE at NORMAL threat level (D-19). */
  readonly challengeThreshold: number;
  /** Trust score above which policy returns DENY at NORMAL threat level (D-19). */
  readonly denyThreshold: number;
  /** Trust score above which policy returns CHALLENGE at ELEVATED threat level (D-19). Tighter than normal. */
  readonly elevatedChallengeThreshold: number;
  /** Trust score above which policy returns DENY at ELEVATED threat level (D-19). Tighter than normal. */
  readonly elevatedDenyThreshold: number;
  /** Trust score above which policy returns CHALLENGE at CRITICAL threat level (D-19). Tighter than elevated. */
  readonly criticalChallengeThreshold: number;
  /** Trust score above which policy returns DENY at CRITICAL threat level (D-19). Tighter than elevated. */
  readonly criticalDenyThreshold: number;
  /** Sliding window length (ms) over which threat signals accumulate. Default 300000 (5min). */
  readonly threatWindowMs: number;
  /** Bounded array capacity per signal type (D-18). Default 10000. */
  readonly threatWindowMaxEvents: number;
  /** Deny count in window that triggers ELEVATED threat level (D-20). Default 20. */
  readonly threatElevatedDenies: number;
  /** Deny count in window that triggers CRITICAL threat level (D-20). Default 50. */
  readonly threatCriticalDenies: number;
  /** Invalid-token count in window that triggers ELEVATED threat level (D-20). Default 30. */
  readonly threatElevatedInvalidTokens: number;
  /** Invalid-token count in window that triggers CRITICAL threat level (D-20). Default 80. */
  readonly threatCriticalInvalidTokens: number;
  /** Honeypot-hit count in window that triggers ELEVATED threat level (D-20). Default 5. */
  readonly threatElevatedHoneypot: number;
  /** Honeypot-hit count in window that triggers CRITICAL threat level (D-20). Default 15. */
  readonly threatCriticalHoneypot: number;
  /** MFA rate-limit hit count in window that triggers ELEVATED threat level (D-09, 14-03). Default 5. */
  readonly threatElevatedMfaRateLimited: number;
  /** MFA rate-limit hit count in window that triggers CRITICAL threat level (D-09, 14-03). Default 15. */
  readonly threatCriticalMfaRateLimited: number;
  /** Cooldown (ms) before threat level can de-escalate. Default 600000 (10min). */
  readonly threatCooldownMs: number;
}

export const POLICY_CONFIG = Symbol('POLICY_CONFIG');

export function buildPolicyConfig(env: ConfigService): PolicyConfig {
  return Object.freeze({
    modelPath: env.get<string>('POLICY_MODEL_PATH'),
    csvPath: env.get<string>('POLICY_CSV_PATH'),
    challengeThreshold: env.get<number>('POLICY_CHALLENGE_THRESHOLD'),
    denyThreshold: env.get<number>('POLICY_DENY_THRESHOLD'),
    elevatedChallengeThreshold: env.get<number>('POLICY_ELEVATED_CHALLENGE_THRESHOLD'),
    elevatedDenyThreshold: env.get<number>('POLICY_ELEVATED_DENY_THRESHOLD'),
    criticalChallengeThreshold: env.get<number>('POLICY_CRITICAL_CHALLENGE_THRESHOLD'),
    criticalDenyThreshold: env.get<number>('POLICY_CRITICAL_DENY_THRESHOLD'),
    threatWindowMs: env.get<number>('THREAT_WINDOW_MS'),
    threatWindowMaxEvents: env.get<number>('THREAT_WINDOW_MAX_EVENTS'),
    threatElevatedDenies: env.get<number>('THREAT_ELEVATED_DENIES'),
    threatCriticalDenies: env.get<number>('THREAT_CRITICAL_DENIES'),
    threatElevatedInvalidTokens: env.get<number>('THREAT_ELEVATED_INVALID_TOKENS'),
    threatCriticalInvalidTokens: env.get<number>('THREAT_CRITICAL_INVALID_TOKENS'),
    threatElevatedHoneypot: env.get<number>('THREAT_ELEVATED_HONEYPOT'),
    threatCriticalHoneypot: env.get<number>('THREAT_CRITICAL_HONEYPOT'),
    threatElevatedMfaRateLimited: env.get<number>('THREAT_ELEVATED_MFA_RATE_LIMITED'),
    threatCriticalMfaRateLimited: env.get<number>('THREAT_CRITICAL_MFA_RATE_LIMITED'),
    threatCooldownMs: env.get<number>('THREAT_COOLDOWN_MS'),
  });
}
