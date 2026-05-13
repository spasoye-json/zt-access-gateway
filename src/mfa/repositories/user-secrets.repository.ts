import { Inject, Injectable } from '@nestjs/common';
import { DB, type Db } from '../../db/db.port';

@Injectable()
export class UserSecretsRepository {
  constructor(@Inject(DB) private readonly db: Db) {}

  /**
   * Returns the AES-256-GCM-encrypted TOTP secret for userId, or null if not provisioned.
   * Caller is responsible for decrypting with aesGcmDecrypt (D-15).
   */
  async getEncryptedSecret(userId: string): Promise<string | null> {
    const r = await this.db.query<{ totp_secret_encrypted: string }>(
      `SELECT totp_secret_encrypted FROM user_secrets WHERE user_id = $1`,
      [userId],
    );
    return r.rows[0]?.totp_secret_encrypted ?? null;
  }

  /**
   * Phase 11 — Upserts the encrypted TOTP secret for userId (D-10).
   * ON CONFLICT (user_id) DO UPDATE makes this idempotent under concurrent
   * confirms — last write wins (T-11-02 acceptable race).
   *
   * SQL is parameterized (T-11-05): user input never interpolated into the statement.
   * created_at is preserved on update; only totp_secret_encrypted changes.
   */
  async save(userId: string, encryptedSecret: string): Promise<void> {
    await this.db.query(
      `INSERT INTO user_secrets (user_id, totp_secret_encrypted)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET totp_secret_encrypted = EXCLUDED.totp_secret_encrypted`,
      [userId, encryptedSecret],
    );
  }

  /**
   * Phase 11 — Admin reset path (D-07). Deletes the user_secrets row for userId.
   * Returns true if a row was deleted, false if no row existed.
   *
   * Parameterized SQL (T-11-05) — no injection surface on the userId param.
   */
  async deleteByUserId(userId: string): Promise<boolean> {
    const r = await this.db.query(`DELETE FROM user_secrets WHERE user_id = $1`, [userId]);
    return (r.rowCount ?? 0) > 0;
  }
}
