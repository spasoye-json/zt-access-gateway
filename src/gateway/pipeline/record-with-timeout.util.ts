import type { Logger } from '@nestjs/common';
import { sleep } from '../../shared/sleep.util';
import type { AuditService } from '../../audit/audit.service';
import type { MetricsService } from '../../metrics/metrics.service';
import type { AuditEntry } from '../../audit/audit-entry.interface';

/**
 * Phase D — Shared best-effort audit write (D-11).
 *
 * Wraps `audit.log(entry)` in a 200ms timeout. On timeout: increments the
 * audit_failures_total counter + emits a warn log; never throws and never
 * blocks the caller. Used by AuthOnlyShortCircuitStage + MfaPromotionStage
 * for CHALLENGE / DENY / AUTH_ONLY audit writes (CLAUDE.md: audit logging
 * is best-effort).
 *
 * Distinct from the audit-ALLOW write (AuditAllowStage), which is fail-closed
 * and throws AuditExhaustedException on WAL exhaustion.
 */
const TIMEOUT_SENTINEL = Symbol('audit_timeout');

export async function recordWithTimeoutBestEffort(
  audit: AuditService,
  metrics: MetricsService,
  logger: Logger,
  entry: AuditEntry,
  timeoutMs = 200,
): Promise<void> {
  const result = await Promise.race<typeof TIMEOUT_SENTINEL | 'OK'>([
    audit.log(entry).then(() => 'OK' as const),
    sleep(timeoutMs).then(() => TIMEOUT_SENTINEL),
  ]);
  if (result === TIMEOUT_SENTINEL) {
    metrics.incrementAuditFailure();
    logger.warn(`audit_timeout requestId=${entry.requestId ?? '?'} decision=${entry.decision}`);
  }
}
