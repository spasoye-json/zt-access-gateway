import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { AppConfigService } from '../config/config.service';
import type { AuditEntry } from './audit-entry.interface';
import type { AuditLog, AuditLogRow } from './audit-log.interface';

export interface AuditLogFilters {
  userId?: string;
  decision?: 'allow' | 'challenge' | 'deny';
  limit: number;
  offset: number;
}

/**
 * Phase 9 — raw pg Pool repository for audit_logs (AUDT-01, AUDT-02, AUDT-05).
 * Mirrors TrustTelemetryRepository: Pool({ max: 5 }), parameterized $N, OnModuleDestroy.
 * INSERT-only at the service level; no UPDATE/DELETE methods (append-only audit trail).
 */
@Injectable()
export class AuditRepository implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(private readonly config: AppConfigService) {
    this.pool = new Pool({ connectionString: this.config.databaseUrl, max: 5 });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  async insert(entry: AuditEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs
         (user_id, resource, action, decision, trust_score, ja4h_fingerprint,
          ip_address, user_agent, request_id, event_type, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
      [
        entry.userId,
        entry.resource,
        entry.action,
        entry.decision,
        entry.trustScore ?? null,
        entry.ja4hFingerprint ?? null,
        entry.ipAddress ?? null,
        entry.userAgent ?? null,
        entry.requestId ?? null,
        entry.eventType ?? null,
      ],
    );
  }

  async findLogs(filters: AuditLogFilters): Promise<{ items: AuditLog[]; total: number }> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.userId !== undefined) {
      params.push(filters.userId);
      where.push(`user_id = $${params.length}`);
    }
    if (filters.decision !== undefined) {
      params.push(filters.decision);
      where.push(`decision = $${params.length}`);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    // Items query — append limit/offset as the last two params
    const itemsParams = [...params, filters.limit, filters.offset];
    const limitIdx = params.length + 1;
    const offsetIdx = params.length + 2;
    const itemsRes = await this.pool.query<AuditLogRow>(
      `SELECT id, user_id, resource, action, decision, trust_score, ja4h_fingerprint,
              ip_address, user_agent, request_id, event_type, created_at
       FROM audit_logs
       ${whereSql}
       ORDER BY created_at DESC
       LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      itemsParams,
    );

    // Count query — same WHERE, no LIMIT/OFFSET
    const countRes = await this.pool.query<{ total: string }>(
      `SELECT COUNT(*)::text AS total FROM audit_logs ${whereSql}`,
      params,
    );

    return {
      items: itemsRes.rows.map(this.toAuditLog),
      total: Number(countRes.rows[0]?.total ?? 0),
    };
  }

  private toAuditLog(row: AuditLogRow): AuditLog {
    return {
      id: Number(row.id),
      userId: row.user_id,
      resource: row.resource,
      action: row.action,
      decision: row.decision,
      trustScore: row.trust_score === null ? null : Number(row.trust_score),
      ja4hFingerprint: row.ja4h_fingerprint,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      requestId: row.request_id,
      eventType: row.event_type,
      createdAt: row.created_at,
    };
  }
}
