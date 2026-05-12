import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AppConfigService } from '../config/config.service';
import { AuditRepository } from './audit.repository';
import { AuditExhaustedException } from './audit-exhausted.exception';
import { sleep } from '../shared/sleep.util';
import type { AuditEntry } from './audit-entry.interface';
import type { AuditLog } from './audit-log.interface';
import type { AuditLogsQueryDto } from './dto/audit-logs-query.dto';

/**
 * Phase 9 — AuditService (AUDT-01, AUDT-03, AUDT-04, AUDT-05, AUDT-06).
 *
 * Two write paths (D-04, D-05):
 *   - writeBlocking() — for ALLOW (audit-before-allow). 3 retries, 50→100→200ms backoff.
 *     Throws AuditExhaustedException on exhaustion → Phase 10 returns 503.
 *   - record() — for CHALLENGE/DENY/HONEYPOT_TRIGGERED. Best-effort, never throws.
 *     On error: console.warn + emit('audit.record_failed') so MetricsService can
 *     increment zt_gateway_audit_failures_total via @OnEvent (D-05). The EventEmitter2
 *     bus (Phase 6 D-13) avoids the circular module dependency that would arise from
 *     direct MetricsService injection (D-03).
 */
@Injectable()
export class AuditService {
  constructor(
    private readonly config: AppConfigService,
    private readonly repo: AuditRepository,
    private readonly events: EventEmitter2,
  ) {}

  /** AUDT-03, AUDT-04 — fail-closed WAL. Throws AuditExhaustedException after maxRetries. */
  async writeBlocking(entry: AuditEntry): Promise<void> {
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

  /** AUDT-01, AUDT-06 — best-effort record (never throws). */
  async record(entry: AuditEntry): Promise<void> {
    try {
      await this.repo.insert(entry);
    } catch (e) {
      // Project convention (CLAUDE.md logging): console.warn for best-effort failures.
      console.warn('[AuditService] best-effort record failed:', e);
      // D-05 — MetricsService @OnEvent('audit.record_failed') increments the counter.
      // EventEmitter2 avoids circular module dep (D-03): both modules import
      // EventEmitterModule, not each other.
      this.events.emit('audit.record_failed');
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
