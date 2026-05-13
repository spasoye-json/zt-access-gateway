import type { ConfigService } from '@nestjs/config';

/**
 * Audit WAL slice (Phase 9 D-06).
 *
 * Exponential backoff for the write-ahead-log path. After walMaxRetries
 * the service throws AuditExhaustedException.
 */
export interface AuditConfig {
  /** Base delay in ms for WAL exponential backoff. Default 50. */
  readonly walBaseDelayMs: number;
  /** Max retries for WAL before throwing AuditExhaustedException. Default 3. */
  readonly walMaxRetries: number;
}

export const AUDIT_CONFIG = Symbol('AUDIT_CONFIG');

export function buildAuditConfig(env: ConfigService): AuditConfig {
  return Object.freeze({
    walBaseDelayMs: env.get<number>('AUDIT_WAL_BASE_DELAY_MS'),
    walMaxRetries: env.get<number>('AUDIT_WAL_MAX_RETRIES'),
  });
}
