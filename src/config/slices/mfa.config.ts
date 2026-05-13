import type { ConfigService } from '@nestjs/config';

/**
 * MFA slice (Phase 7 D-09, D-15, D-03, D-17 + Phase 11 D-11).
 *
 * Separate JWT secret from auth (D-09). AES-256-GCM key for TOTP secrets at rest.
 * Joi cross-field validator enforces challengeTtlMs < tokenTtlMs at boot.
 */
export interface MfaConfig {
  /** Separate from JWT_SECRET (D-09). Joi min 32 chars. */
  readonly jwtSecret: string;
  /** AES-256-GCM key for TOTP secrets at rest (D-15). Base64-encoded 32-byte key. Joi min(44). */
  readonly totpEncryptionKey: string;
  /** Challenge row TTL in ms (D-03). Default 300000 (5min). Must be < tokenTtlMs. */
  readonly challengeTtlMs: number;
  /** MFA JWT TTL in ms (D-03). Default 600000 (10min). */
  readonly tokenTtlMs: number;
  /** Max challenges per user per rateLimitWindowMs (D-17). Default 5. */
  readonly rateLimitMax: number;
  /** Rate-limit window in ms (D-17). Default 60000. */
  readonly rateLimitWindowMs: number;
  /** TOTP issuer name shown in authenticator apps. Joi default 'ZT-Gateway'. */
  readonly issuerName: string;
  /** TTL for pending enrollment entries in ms. Joi default 600000 (10min). */
  readonly enrollPendingTtlMs: number;
}

export const MFA_CONFIG = Symbol('MFA_CONFIG');

export function buildMfaConfig(env: ConfigService): MfaConfig {
  return Object.freeze({
    jwtSecret: env.get<string>('MFA_JWT_SECRET')!,
    totpEncryptionKey: env.get<string>('MFA_TOTP_ENCRYPTION_KEY')!,
    challengeTtlMs: env.get<number>('MFA_CHALLENGE_TTL_MS')!,
    tokenTtlMs: env.get<number>('MFA_TOKEN_TTL_MS')!,
    rateLimitMax: env.get<number>('MFA_RATE_LIMIT_MAX')!,
    rateLimitWindowMs: env.get<number>('MFA_RATE_LIMIT_WINDOW_MS')!,
    issuerName: env.get<string>('MFA_ISSUER_NAME')!,
    enrollPendingTtlMs: env.get<number>('MFA_ENROLL_PENDING_TTL_MS')!,
  });
}
