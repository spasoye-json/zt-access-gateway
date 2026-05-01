import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { AppConfigService } from '../../config/config.service';

export interface MfaTokenRow {
  jti: string;
  userId: string;
  fingerprintHash: string;
  issuedAt: Date;
  expiresAt: Date;
}

@Injectable()
export class MfaTokenRepository implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(private readonly config: AppConfigService) {
    this.pool = new Pool({ connectionString: this.config.databaseUrl, max: 5 });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Insert MFA token row. Retries once on jti UUID collision (Pitfall 3 — pg error 23505).
   */
  async insertMfaToken(
    jti: string,
    userId: string,
    fingerprintHash: string,
    expiresAt: Date,
  ): Promise<void> {
    const tryInsert = async (id: string): Promise<void> => {
      await this.pool.query(
        `INSERT INTO mfa_tokens (jti, user_id, fingerprint_hash, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [id, userId, fingerprintHash, expiresAt],
      );
    };
    try {
      await tryInsert(jti);
    } catch (err: unknown) {
      if ((err as { code?: string }).code === '23505') {
        // UUID collision — retry with fresh UUID (Pitfall 3)
        await tryInsert(randomUUID());
      } else {
        throw err;
      }
    }
  }

  /**
   * Returns token row if jti is valid: not revoked and not expired.
   * Returns null otherwise.
   */
  async getMfaToken(jti: string): Promise<MfaTokenRow | null> {
    const r = await this.pool.query<{
      jti: string;
      user_id: string;
      fingerprint_hash: string;
      issued_at: Date;
      expires_at: Date;
    }>(
      `SELECT jti, user_id, fingerprint_hash, issued_at, expires_at
       FROM mfa_tokens
       WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
      [jti],
    );
    if (!r.rows[0]) return null;
    const row = r.rows[0];
    return {
      jti: row.jti,
      userId: row.user_id,
      fingerprintHash: row.fingerprint_hash,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
    };
  }

  async revokeMfaToken(jti: string): Promise<void> {
    await this.pool.query(`UPDATE mfa_tokens SET revoked_at = NOW() WHERE jti = $1`, [jti]);
  }
}
