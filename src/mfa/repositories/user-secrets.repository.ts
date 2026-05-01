import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { AppConfigService } from '../../config/config.service';

@Injectable()
export class UserSecretsRepository implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(private readonly config: AppConfigService) {
    this.pool = new Pool({ connectionString: this.config.databaseUrl, max: 5 });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Returns the AES-256-GCM-encrypted TOTP secret for userId, or null if not provisioned.
   * Caller is responsible for decrypting with aesGcmDecrypt (D-15).
   */
  async getEncryptedSecret(userId: string): Promise<string | null> {
    const r = await this.pool.query<{ totp_secret_encrypted: string }>(
      `SELECT totp_secret_encrypted FROM user_secrets WHERE user_id = $1`,
      [userId],
    );
    return r.rows[0]?.totp_secret_encrypted ?? null;
  }
}
