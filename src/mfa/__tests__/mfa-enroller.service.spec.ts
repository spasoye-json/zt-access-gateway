/**
 * Phase C (260513-mar) — MfaEnroller unit tests.
 *
 * Mirrors the enrollment-half describe blocks (createEnrollment,
 * confirmEnrollment, deleteEnrollment) of the old mfa.service.spec.ts.
 * Adapted for the post-split surface: MfaErrorRecorder is now an injected
 * collaborator, and ENROLL_MAX_ATTEMPTS lives on MfaEnroller.
 */
import { totp as authenticator } from '../../shared/totp.util';
import { Test } from '@nestjs/testing';
import { TypedEvents } from '../../shared/typed-events';

import {
  MfaEnroller,
  type MfaEnrollResult,
  type MfaConfirmResult,
  type MfaDeleteEnrollmentResult,
} from '../mfa-enroller.service';
import { UserSecretsRepository } from '../repositories/user-secrets.repository';
import { MFA_CONFIG, type MfaConfig } from '../../config/slices';
import { aesGcmEncrypt, aesGcmDecrypt } from '../../shared/aes-gcm.util';
import { MFA_FAILED, MFA_INFRA_ERROR, MFA_RATE_LIMITED } from '../../policy/policy-events';
import { PendingEnrollmentStore } from '../enrollment.store';
import { MfaErrorRecorder } from '../mfa-error-recorder.util';

const TEST_ENC_KEY = Buffer.alloc(32, 0x42).toString('base64');
const TEST_TOTP_SECRET = authenticator.generateSecret();
const TEST_ENC_TOTP = aesGcmEncrypt(TEST_TOTP_SECRET, TEST_ENC_KEY);
const TEST_USER = 'user-123';
const TEST_IP = '10.0.0.1';

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

function assertOkTrue<T extends { ok: true }>(result: { ok: boolean }): asserts result is T {
  if (!result.ok) throw new Error('Expected ok:true');
}
function assertOkFalse<T extends { ok: false }>(result: { ok: boolean }): asserts result is T {
  if (result.ok) throw new Error('Expected ok:false');
}

describe('MfaEnroller', () => {
  let service: MfaEnroller;
  let secretsRepo: jest.Mocked<UserSecretsRepository>;
  let emitter: jest.Mocked<TypedEvents>;
  let errorRecorder: { record: jest.Mock };
  let pendingStore: {
    set: jest.Mock;
    get: jest.Mock;
    delete: jest.Mock;
    size: jest.Mock;
    clear: jest.Mock;
    hasPendingForUser: jest.Mock;
    incrementAttempts: jest.Mock;
  };

  beforeEach(async () => {
    secretsRepo = {
      getEncryptedSecret: jest.fn().mockResolvedValue(TEST_ENC_TOTP),
      save: jest.fn().mockResolvedValue(undefined),
      deleteByUserId: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<UserSecretsRepository>;

    emitter = { emit: jest.fn() } as unknown as jest.Mocked<TypedEvents>;
    errorRecorder = { record: jest.fn() };

    pendingStore = {
      set: jest.fn(),
      get: jest.fn().mockReturnValue(null),
      delete: jest.fn(),
      size: jest.fn().mockReturnValue(0),
      clear: jest.fn(),
      hasPendingForUser: jest.fn().mockReturnValue(false),
      incrementAttempts: jest.fn().mockReturnValue(1),
    };

    const module = await Test.createTestingModule({
      providers: [
        MfaEnroller,
        { provide: MFA_CONFIG, useValue: buildMockConfig() },
        { provide: UserSecretsRepository, useValue: secretsRepo },
        { provide: TypedEvents, useValue: emitter },
        { provide: MfaErrorRecorder, useValue: errorRecorder },
        { provide: PendingEnrollmentStore, useValue: pendingStore },
      ],
    }).compile();

    service = module.get(MfaEnroller);
  });

  // ---------------------------------------------------------------------------
  // createEnrollment()
  // ---------------------------------------------------------------------------
  describe('createEnrollment()', () => {
    it('ENROLL-01: returns { enrollmentId, otpauthUri } for unenrolled user', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(null);
      const result: MfaEnrollResult = await service.createEnrollment(
        TEST_USER,
        'alice@example.com',
      );
      assertOkTrue<Extract<MfaEnrollResult, { ok: true }>>(result);
      expect(result.enrollmentId).toMatch(/^[0-9a-f-]{36}$/);
      expect(result.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
      expect(pendingStore.set).toHaveBeenCalledTimes(1);
      const [eid, entry] = pendingStore.set.mock.calls[0];
      expect(eid).toBe(result.enrollmentId);
      expect(entry.userId).toBe(TEST_USER);
      expect(typeof entry.secret).toBe('string');
      expect(entry.secret.length).toBeGreaterThanOrEqual(16);
    });

    it('ENROLL-02: otpauthUri contains algorithm=SHA1, digits=6, period=30, issuer, label', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(null);
      const result = await service.createEnrollment(TEST_USER, 'alice@example.com');
      assertOkTrue<Extract<MfaEnrollResult, { ok: true }>>(result);
      expect(result.otpauthUri).toContain('algorithm=SHA1');
      expect(result.otpauthUri).toContain('digits=6');
      expect(result.otpauthUri).toContain('period=30');
      expect(result.otpauthUri).toContain('issuer=Test-Issuer');
      expect(result.otpauthUri).toContain('Test-Issuer:alice%40example.com');
    });

    it('ENROLL-02b: falls back to userId as label when email is absent', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(null);
      const result = await service.createEnrollment(TEST_USER);
      assertOkTrue<Extract<MfaEnrollResult, { ok: true }>>(result);
      expect(result.otpauthUri).toContain(`Test-Issuer:${TEST_USER}`);
      expect(result.otpauthUri).not.toContain('undefined');
    });

    it('ENROLL-03: returns { ok: false, reason: already_enrolled } when user_secrets row exists', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(TEST_ENC_TOTP);
      const result = await service.createEnrollment(TEST_USER, 'alice@example.com');
      assertOkFalse<Extract<MfaEnrollResult, { ok: false }>>(result);
      expect(result.reason).toBe('already_enrolled');
      expect(pendingStore.set).not.toHaveBeenCalled();
    });

    it('ENROLL-03b: returns { ok: false, reason: already_enrolled } when pending enrollment exists', async () => {
      pendingStore.hasPendingForUser.mockReturnValue(true);
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(null);
      const result = await service.createEnrollment(TEST_USER, 'alice@example.com');
      assertOkFalse<Extract<MfaEnrollResult, { ok: false }>>(result);
      expect(result.reason).toBe('already_enrolled');
      expect(pendingStore.set).not.toHaveBeenCalled();
    });

    it('returns { ok: false, reason: internal } if repo throws', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockRejectedValue(new Error('db down'));
      const result = await service.createEnrollment(TEST_USER, 'alice@example.com');
      assertOkFalse<Extract<MfaEnrollResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
    });

    it('WR-03: createEnrollment infra error delegates to MfaErrorRecorder', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockRejectedValue(new Error('db down'));
      await service.createEnrollment(TEST_USER, 'alice@example.com');
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaEnroller',
        'createEnrollment',
        TEST_USER,
        expect.any(Error),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // confirmEnrollment()
  // ---------------------------------------------------------------------------
  describe('confirmEnrollment()', () => {
    const ENROLL_ID = 'enroll-uuid-001';
    const TEST_PENDING_SECRET = authenticator.generateSecret();
    const validCode = (): string => authenticator.generate(TEST_PENDING_SECRET);

    beforeEach(() => {
      pendingStore.get.mockReturnValue({
        userId: TEST_USER,
        secret: TEST_PENDING_SECRET,
        expiresAt: Date.now() + 60_000,
      });
    });

    it('ENROLL-04: writes encrypted secret and deletes pending entry on valid TOTP', async () => {
      const result: MfaConfirmResult = await service.confirmEnrollment(
        ENROLL_ID,
        validCode(),
        TEST_USER,
      );
      assertOkTrue<Extract<MfaConfirmResult, { ok: true }>>(result);
      expect(secretsRepo.save).toHaveBeenCalledTimes(1);
      const [savedUser, savedEnc] = (secretsRepo.save as jest.Mock).mock.calls[0];
      expect(savedUser).toBe(TEST_USER);
      expect(aesGcmDecrypt(savedEnc, TEST_ENC_KEY)).toBe(TEST_PENDING_SECRET);
      expect(pendingStore.delete).toHaveBeenCalledWith(ENROLL_ID);
    });

    it('ENROLL-05: returns invalid_totp on wrong code; pending entry NOT deleted (within attempt cap)', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      const result = await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('invalid_totp');
      expect(pendingStore.delete).not.toHaveBeenCalled();
      expect(secretsRepo.save).not.toHaveBeenCalled();
    });

    it('BL-02: emits MFA_FAILED on invalid TOTP during enrollment', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed.p as { reason: string }).reason).toBe('invalid_totp_enrollment');
      expect((failed.p as { userId: string }).userId).toBe(TEST_USER);
    });

    it('BL-02: increments the per-enrollmentId attempt counter on each failure', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      expect(pendingStore.incrementAttempts).toHaveBeenCalledWith(ENROLL_ID);
    });

    it('BL-02: on attempts >= ENROLL_MAX_ATTEMPTS deletes pending and emits MFA_RATE_LIMITED', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaEnroller.ENROLL_MAX_ATTEMPTS);
      const result = await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('invalid_totp');
      expect(pendingStore.delete).toHaveBeenCalledWith(ENROLL_ID);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_RATE_LIMITED);
    });

    it('BL-02: under the attempt cap does NOT emit MFA_RATE_LIMITED', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaEnroller.ENROLL_MAX_ATTEMPTS - 1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).not.toContain(MFA_RATE_LIMITED);
      expect(pendingStore.delete).not.toHaveBeenCalled();
    });

    it('IN-04: MFA_FAILED on invalid enrollment TOTP carries ip + ja4h', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP, 'ja4h-enroll-1');
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed.p as { ip: string }).ip).toBe(TEST_IP);
      expect((failed.p as { ja4h?: string }).ja4h).toBe('ja4h-enroll-1');
    });

    it('IN-04: MFA_RATE_LIMITED on attempts exhausted carries ip + ja4h', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaEnroller.ENROLL_MAX_ATTEMPTS);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP, 'ja4h-enroll-2');
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const rateLimited = calls.find((c) => c.name === MFA_RATE_LIMITED);
      expect(rateLimited).toBeDefined();
      expect((rateLimited.p as { ip: string }).ip).toBe(TEST_IP);
      expect((rateLimited.p as { ja4h?: string }).ja4h).toBe('ja4h-enroll-2');
    });

    it('IN-04: omits ja4h key when caller does not supply it', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP);
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed.p as { ip: string }).ip).toBe(TEST_IP);
      expect((failed.p as { ja4h?: string }).ja4h).toBeUndefined();
    });

    it('ENROLL-06b: returns expired_enrollment when pending entry missing/expired', async () => {
      pendingStore.get.mockReturnValue(null);
      const result = await service.confirmEnrollment(ENROLL_ID, validCode(), TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('expired_enrollment');
      expect(secretsRepo.save).not.toHaveBeenCalled();
    });

    it('T-11-01: returns user_mismatch when pending.userId differs from caller userId', async () => {
      pendingStore.get.mockReturnValue({
        userId: 'other-user',
        secret: TEST_PENDING_SECRET,
        expiresAt: Date.now() + 60_000,
      });
      const result = await service.confirmEnrollment(ENROLL_ID, validCode(), TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('user_mismatch');
      expect(secretsRepo.save).not.toHaveBeenCalled();
      expect(pendingStore.delete).not.toHaveBeenCalled();
    });

    it('returns internal when secretsRepo.save throws', async () => {
      (secretsRepo.save as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      const result = await service.confirmEnrollment(ENROLL_ID, validCode(), TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
    });

    it('WR-03: confirmEnrollment infra error delegates to MfaErrorRecorder', async () => {
      (secretsRepo.save as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      await service.confirmEnrollment(ENROLL_ID, validCode(), TEST_USER);
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaEnroller',
        'confirmEnrollment',
        TEST_USER,
        expect.any(Error),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // deleteEnrollment()
  // ---------------------------------------------------------------------------
  describe('deleteEnrollment()', () => {
    it('ENROLL-07: returns { ok: true, deleted: true } when row exists', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockResolvedValueOnce(true);
      const result: MfaDeleteEnrollmentResult = await service.deleteEnrollment(TEST_USER);
      assertOkTrue<Extract<MfaDeleteEnrollmentResult, { ok: true }>>(result);
      expect(result.deleted).toBe(true);
      expect(secretsRepo.deleteByUserId).toHaveBeenCalledWith(TEST_USER);
    });

    it('ENROLL-08: returns { ok: true, deleted: false } when row does not exist', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockResolvedValueOnce(false);
      const result = await service.deleteEnrollment(TEST_USER);
      assertOkTrue<Extract<MfaDeleteEnrollmentResult, { ok: true }>>(result);
      expect(result.deleted).toBe(false);
    });

    it('emits mfa.enrollment_reset event on successful delete (admin reset audit)', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockResolvedValueOnce(true);
      await service.deleteEnrollment(TEST_USER);
      expect(emitter.emit).toHaveBeenCalledWith(
        'mfa.enrollment_reset',
        expect.objectContaining({ type: 'mfa.enrollment_reset', userId: TEST_USER }),
      );
    });

    it('returns internal when repo throws', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      const result = await service.deleteEnrollment(TEST_USER);
      assertOkFalse<Extract<MfaDeleteEnrollmentResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
    });

    it('WR-03: deleteEnrollment infra error delegates to MfaErrorRecorder', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      await service.deleteEnrollment(TEST_USER);
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaEnroller',
        'deleteEnrollment',
        TEST_USER,
        expect.any(Error),
      );
    });
  });

  // Smoke check that the policy-events symbol the recorder uses is still
  // exported (defends against accidental refactor of the events module).
  describe('infra error routing', () => {
    it('MFA_INFRA_ERROR symbol exported by policy-events', () => {
      expect(typeof MFA_INFRA_ERROR).toBe('string');
    });
  });
});
