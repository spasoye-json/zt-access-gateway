/**
 * Ticket #34 (Phase 11) — TOTP secret is stored encrypted (AES-256-GCM) at rest.
 *
 * Codifies item #1 of the HUMAN-UAT: a full enroll → confirm round-trip wires the
 * real MfaEnroller + real UserSecretsRepository over an in-memory Db double, so the
 * assertion runs WITHOUT live Postgres (no DATABASE_URL required, never skips).
 *
 * What it proves:
 *   - confirmEnrollment persists the secret as ciphertext, NOT the plaintext base32 secret.
 *   - the persisted blob round-trips through aesGcmDecrypt back to the original secret.
 *   - the ciphertext format matches the GCM helper contract (base64, ≥ iv+tag length).
 */
import { Test } from '@nestjs/testing';
import type { QueryResult } from 'pg';
import { MfaEnroller } from '../../src/mfa/mfa-enroller.service';
import { UserSecretsRepository } from '../../src/mfa/repositories/user-secrets.repository';
import { PendingEnrollmentStore } from '../../src/mfa/enrollment.store';
import { MfaErrorRecorder } from '../../src/mfa/mfa-error-recorder.util';
import { TypedEvents } from '../../src/shared/typed-events';
import { MFA_CONFIG, type MfaConfig } from '../../src/config/slices';
import { DB, type Db } from '../../src/db/db.port';
import { aesGcmDecrypt } from '../../src/shared/aes-gcm.util';
import { totp as authenticator } from '../../src/shared/totp.util';

const TEST_ENC_KEY = Buffer.alloc(32, 0x11).toString('base64');
const TEST_USER = 'enc-at-rest-user';

function buildMockConfig(): Partial<MfaConfig> {
  return {
    jwtSecret: 'irrelevant-for-enroller-but-required-by-shape',
    totpEncryptionKey: TEST_ENC_KEY,
    challengeTtlMs: 300_000,
    tokenTtlMs: 600_000,
    rateLimitMax: 5,
    rateLimitWindowMs: 60_000,
    issuerName: 'Test-Issuer',
    enrollPendingTtlMs: 600_000,
  };
}

/**
 * In-memory Db double: a single user_secrets row keyed by user_id. Implements only
 * the INSERT … ON CONFLICT upsert and SELECT the repository issues — enough to assert
 * what actually lands in storage. tx() is unused on this path.
 */
function buildInMemoryDb(store: Map<string, string>): Db {
  return {
    async query<R = unknown>(
      sql: string,
      params?: ReadonlyArray<unknown>,
    ): Promise<QueryResult<R>> {
      const text = sql.trim();
      if (/^INSERT INTO user_secrets/i.test(text)) {
        const [userId, encrypted] = params as [string, string];
        store.set(userId, encrypted);
        return { rows: [], rowCount: 1 } as unknown as QueryResult<R>;
      }
      if (/^SELECT totp_secret_encrypted FROM user_secrets/i.test(text)) {
        const [userId] = params as [string];
        const enc = store.get(userId);
        const rows = enc === undefined ? [] : [{ totp_secret_encrypted: enc }];
        return { rows, rowCount: rows.length } as unknown as QueryResult<R>;
      }
      return { rows: [], rowCount: 0 } as unknown as QueryResult<R>;
    },
    async tx<R>(): Promise<R> {
      throw new Error('tx not used on the enrollment path');
    },
  };
}

function secretFromUri(otpauthUri: string): string {
  const m = otpauthUri.match(/secret=([^&]+)/);
  if (!m) throw new Error('otpauth URI missing secret param');
  return m[1];
}

function requirePersisted(store: Map<string, string>, userId: string): string {
  const persisted = store.get(userId);
  if (persisted === undefined) throw new Error('expected user_secrets row to be persisted');
  return persisted;
}

describe('Ticket #34 — TOTP secret encrypted (AES-256-GCM) at rest', () => {
  let enroller: MfaEnroller;
  let store: Map<string, string>;

  beforeEach(async () => {
    store = new Map<string, string>();
    const module = await Test.createTestingModule({
      providers: [
        MfaEnroller,
        UserSecretsRepository,
        PendingEnrollmentStore,
        MfaErrorRecorder,
        { provide: MFA_CONFIG, useValue: buildMockConfig() },
        { provide: DB, useValue: buildInMemoryDb(store) },
        { provide: TypedEvents, useValue: { emit: jest.fn() } },
      ],
    }).compile();

    enroller = module.get(MfaEnroller);
  });

  it('ENROLL-D15: confirmEnrollment stores ciphertext, NOT the plaintext base32 secret', async () => {
    const enroll = await enroller.createEnrollment(TEST_USER);
    if (!enroll.ok) throw new Error('expected enroll ok');
    const plaintextSecret = secretFromUri(enroll.otpauthUri);

    const code = authenticator.generate(plaintextSecret);
    const confirm = await enroller.confirmEnrollment(enroll.enrollmentId, code, TEST_USER);
    expect(confirm.ok).toBe(true);

    const persisted = requirePersisted(store, TEST_USER);
    // The stored blob must not be the raw base32 secret.
    expect(persisted).not.toBe(plaintextSecret);
    expect(persisted).not.toContain(plaintextSecret);
    // GCM helper contract: base64 of iv(12) || ciphertext || authTag(16).
    expect(persisted).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(Buffer.from(persisted, 'base64').length).toBeGreaterThanOrEqual(12 + 16);
  });

  it('ENROLL-D15: the persisted ciphertext round-trips via aesGcmDecrypt to the original secret', async () => {
    const enroll = await enroller.createEnrollment(TEST_USER);
    if (!enroll.ok) throw new Error('expected enroll ok');
    const plaintextSecret = secretFromUri(enroll.otpauthUri);

    const code = authenticator.generate(plaintextSecret);
    await enroller.confirmEnrollment(enroll.enrollmentId, code, TEST_USER);

    const persisted = requirePersisted(store, TEST_USER);
    expect(aesGcmDecrypt(persisted, TEST_ENC_KEY)).toBe(plaintextSecret);
    // Wrong key must NOT decrypt (GCM auth-tag rejection → null).
    expect(aesGcmDecrypt(persisted, Buffer.alloc(32, 0x99).toString('base64'))).toBeNull();
  });
});
