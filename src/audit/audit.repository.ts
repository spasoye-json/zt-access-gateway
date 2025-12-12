import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool, PoolClient } from 'pg';
import { AuditLog } from './audit.service';

@Injectable()
export class AuditRepository implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AuditRepository.name);
  private pool: Pool | null = null;
  private enabled = false;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const connectionString = this.configService.get<string>('DATABASE_URL');

    if (!connectionString) {
      this.logger.warn('DATABASE_URL not set; persistent audit logging disabled');
      return;
    }

    this.pool = new Pool({ connectionString });
    let client: PoolClient | null = null;
    try {
      client = await this.pool.connect();
      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          request_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          microservice TEXT NOT NULL,
          decision TEXT NOT NULL,
          risk_score DOUBLE PRECISION NOT NULL,
          policy_applied TEXT NOT NULL,
          metadata JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
      `);
      this.enabled = true;
      this.logger.log('Audit repository initialized (Postgres)');
    } catch (error) {
      this.logger.error(`Failed to initialize audit table: ${error.message}`);
      this.enabled = false;
      if (this.pool) {
        await this.pool.end().catch(() => undefined);
        this.pool = null;
      }
    } finally {
      client?.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.pool) {
      await this.pool.end().catch(() => undefined);
      this.pool = null;
    }
  }

  isEnabled(): boolean {
    return this.enabled && !!this.pool;
  }

  async persist(log: AuditLog): Promise<void> {
    if (!this.isEnabled() || !this.pool) {
      return;
    }

    let client: PoolClient | null = null;
    try {
      client = await this.pool.connect();
      await client.query(
        `
        INSERT INTO audit_logs (
          id,
          request_id,
          user_id,
          microservice,
          decision,
          risk_score,
          policy_applied,
          metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
        [
          log.id,
          log.requestId,
          log.userId,
          log.microservice,
          log.decision,
          log.riskScore,
          log.policyApplied,
          JSON.stringify(log.metadata ?? {}),
        ],
      );
    } catch (error) {
      this.logger.warn(`Failed to persist audit log (requestId=${log.requestId}): ${error.message}`);
    } finally {
      client?.release();
    }
  }
}
