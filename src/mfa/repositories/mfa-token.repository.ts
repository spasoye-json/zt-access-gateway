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

  /**
   * Returns jti status row without applying revoked/expired filters.
   * Used by validateMfaToken to distinguish unknown_jti from revoked (Fix-2).
   * Returns null if no row exists for the given jti.
   *
   * NOTE (phase 14 WR-01): kept for backwards compatibility but the validation
   * code path now uses getMfaTokenWithStatus to collapse the previous two-query
   * race window. Prefer the atomic variant below.
   */
  async getMfaTokenStatus(
    jti: string,
  ): Promise<{ isRevoked: boolean; isExpired: boolean } | null> {
    const r = await this.pool.query<{
      is_revoked: boolean;
      is_expired: boolean;
    }>(
      `SELECT
         revoked_at IS NOT NULL AS is_revoked,
         expires_at < NOW()    AS is_expired
       FROM mfa_tokens
       WHERE jti = $1`,
      [jti],
    );
    if (!r.rows[0]) return null;
    return {
      isRevoked: r.rows[0].is_revoked,
      isExpired: r.rows[0].is_expired,
    };
  }

  /**
   * WR-01 (phase 14): atomic single-SELECT that returns the full row + the
   * computed revoked/expired flags in one round-trip. Closes a revocation
   * TOCTOU window where a concurrent admin revoke between the previous
   * getMfaTokenStatus and getMfaToken calls would let a now-revoked token
   * pass the fingerprint check and validate as OK.
   *
   * Returns null when no row exists for this jti.
   */
  async getMfaTokenWithStatus(jti: string): Promise<
    | (MfaTokenRow & { isRevoked: boolean; isExpired: boolean })
    | null
  > {
    const r = await this.pool.query<{
      jti: string;
      user_id: string;
      fingerprint_hash: string;
      issued_at: Date;
      expires_at: Date;
      is_revoked: boolean;
      is_expired: boolean;
    }>(
      `SELECT
         jti,
         user_id,
         fingerprint_hash,
         issued_at,
         expires_at,
         revoked_at IS NOT NULL AS is_revoked,
         expires_at <= NOW()    AS is_expired
       FROM mfa_tokens
       WHERE jti = $1`,
      [jti],
    );
    const row = r.rows[0];
    if (!row) return null;
    return {
      jti: row.jti,
      userId: row.user_id,
      fingerprintHash: row.fingerprint_hash,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      isRevoked: row.is_revoked,
      isExpired: row.is_expired,
    };
  }
}
