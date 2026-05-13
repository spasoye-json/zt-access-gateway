import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';
import { AuditRepository } from './audit.repository';
import { AuditExhaustedException } from './audit-exhausted.exception';
import { sleep } from '../shared/sleep.util';
import { TypedEvents } from '../shared/typed-events';
import { AUDIT_RECORD_FAILED } from '../metrics/metrics-events';
import type { AuditEntry } from './audit-entry.interface';
import type { AuditLog } from './audit-log.interface';
import type { AuditLogsQueryDto } from './dto/audit-logs-query.dto';

/**
 * Phase 9 — AuditService (AUDT-01, AUDT-03, AUDT-04, AUDT-05, AUDT-06).
 *
 * Single public write port: `log(entry)`. Dispatches internally on
 * `entry.decision` (Phase A1 of polymorphic-juggling-haven refactor):
 *
 *   - `decision === 'allow'`        → fail-closed WAL (D-04 retry loop, 50→100→200ms
 *                                     backoff). Throws AuditExhaustedException after
 *                                     maxRetries → GatewayMiddleware central catch
 *                                     maps to HTTP 503 + Retry-After: 5.
 *   - `decision === 'challenge'`    → best-effort (D-05). Never throws.
 *   - `decision === 'deny'`         → best-effort. Never throws. Includes the
 *     (with `eventType: 'HONEYPOT_TRIGGERED'`   AUDT-06 honeypot variant — discriminator is
 *     or not)                                   the decision value, not eventType.
 *
 * On best-effort error: console.warn + emit('audit.record_failed') so
 * MetricsService can increment zt_gateway_audit_failures_total via @OnEvent
 * (D-05). The EventEmitter2 bus (Phase 6 D-13) avoids the circular module
 * dependency that would arise from direct MetricsService injection (D-03).
 */
@Injectable()
export class AuditService {
  constructor(
    private readonly config: AppConfigService,
    private readonly repo: AuditRepository,
    private readonly events: TypedEvents,
  ) {}

  /**
   * Unified write port. Dispatches on `entry.decision`:
   *   'allow'   → fail-closed WAL (may throw AuditExhaustedException)
   *   else      → best-effort (never throws; emits 'audit.record_failed' on error)
   */
  async log(entry: AuditEntry): Promise<void> {
    if (entry.decision === 'allow') {
      return this.writeBlocking(entry);
    }
    return this.recordBestEffort(entry);
  }

  /** AUDT-03, AUDT-04 — fail-closed WAL. Throws AuditExhaustedException after maxRetries. */
  private async writeBlocking(entry: AuditEntry): Promise<void> {
    const maxRetries = this.config.auditWalMaxRetries;
    const baseDelay = this.config.auditWalBaseDelayMs;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        await this.repo.insert(entry);
        return;
      } catch {
        if (attempt < maxRetries - 1) {
          await sleep(baseDelay * Math.pow(2, attempt));
        }
      }
    }
    throw new AuditExhaustedException(`Audit WAL exhausted after ${maxRetries} retries`);
  }

  /** AUDT-01, AUDT-06 — best-effort record (never throws). D-05/D-13 — emits via bus. */
  private async recordBestEffort(entry: AuditEntry): Promise<void> {
    try {
      await this.repo.insert(entry);
    } catch (e) {
      // Project convention (CLAUDE.md logging): console.warn for best-effort failures.
      console.warn('[AuditService] best-effort record failed:', e);
      // D-05 — MetricsService @OnEvent('audit.record_failed') increments the counter.
      // EventEmitter2 avoids circular module dep (D-03): both modules import
      // EventEmitterModule, not each other.
      this.events.emit(AUDIT_RECORD_FAILED);
    }
  }

  /** AUDT-05 — admin query path. Defaults: limit 50, offset 0. */
  async queryLogs(q: AuditLogsQueryDto): Promise<{ items: AuditLog[]; total: number }> {
    return this.repo.findLogs({
      userId: q.userId,
      decision: q.decision,
      limit: q.limit ?? 50,
      offset: q.offset ?? 0,
    });
  }
}
