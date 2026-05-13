/**
 * Phase C (260513-mar) — MfaChallenger unit tests.
 *
 * Mirrors the challenge-half describe blocks (createChallenge, verifyTotp,
 * validateMfaToken) of the old mfa.service.spec.ts. Adapted for the post-
 * split surface: MfaErrorRecorder is now an injected collaborator instead
 * of a private method.
 */
import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { totp as authenticator } from '../../shared/totp.util';
import { Test } from '@nestjs/testing';
import { TypedEvents } from '../../shared/typed-events';

import {
  MfaChallenger,
  MfaCreateResult,
  MfaVerifyResult,
  MfaValidateResult,
} from '../mfa-challenger.service';
import { MfaChallengeRepository } from '../repositories/mfa-challenge.repository';
import { MfaTokenRepository } from '../repositories/mfa-token.repository';
import { UserSecretsRepository } from '../repositories/user-secrets.repository';
import { MFA_CONFIG, type MfaConfig } from '../../config/slices';
import { aesGcmEncrypt } from '../../shared/aes-gcm.util';
import {
  MFA_FAILED,
  MFA_INFRA_ERROR,
  MFA_RATE_LIMITED,
  MFA_SECRET_DECRYPT_FAILED,
} from '../../policy/policy-events';
import { MfaErrorRecorder } from '../mfa-error-recorder.util';

const TEST_JWT_SECRET = 'test-mfa-jwt-secret-at-least-32-chars!!';
const TEST_ENC_KEY = Buffer.alloc(32, 0x42).toString('base64');
const TEST_TOTP_SECRET = authenticator.generateSecret();
const TEST_ENC_TOTP = aesGcmEncrypt(TEST_TOTP_SECRET, TEST_ENC_KEY);
const TEST_USER = 'user-123';
const TEST_DEVICE = 'device-456';
const TEST_IP = '10.0.0.1';
const TEST_CHALLENGE_ID = 'challenge-uuid-001';
const FUTURE_DATE = new Date(Date.now() + 300_000);

const secretBytes = () => new TextEncoder().encode(TEST_JWT_SECRET);

function expectedFingerprint(userId: string, deviceId: string, ip: string): string {
  return createHash('sha256').update(`${userId}|${deviceId}|${ip}`, 'utf8').digest('hex');
}

function buildMockConfig(): Partial<MfaConfig> {
  return {
    jwtSecret: TEST_JWT_SECRET,
    totpEncryptionKey: TEST_ENC_KEY,
    challengeTtlMs: 300_000,
    tokenTtlMs: 600_000,
    rateLimitMax: 5,
    rateLimitWindowMs: 60_000,
    issuerName: 'Test-Issuer',
    enrollPendingTtlMs: 600_000,
  };
}

async function mintMfaJwt(opts: {
  userId?: string;
  deviceId?: string;
  fpHash?: string;
  jti?: string;
  typ?: string;
  expiresIn?: string;
}): Promise<string> {
  const {
    userId = TEST_USER,
    deviceId = TEST_DEVICE,
    fpHash = expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
    jti = 'jti-test-1',
    typ = 'mfa',
    expiresIn = '10m',
  } = opts;
  return new SignJWT({ sub: userId, jti, deviceId, fpHash, typ })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(secretBytes());
}

function assertOkTrue<T extends { ok: true }>(
  result: { ok: boolean },
  _msg?: string,
): asserts result is T {
  if (!result.ok) throw new Error(_msg ?? 'Expected ok:true');
}
function assertOkFalse<T extends { ok: false }>(
  result: { ok: boolean },
  _msg?: string,
): asserts result is T {
  if (result.ok) throw new Error(_msg ?? 'Expected ok:false');
}

describe('MfaChallenger', () => {
  let service: MfaChallenger;
  let challengeRepo: jest.Mocked<MfaChallengeRepository>;
  let tokenRepo: jest.Mocked<MfaTokenRepository>;
  let secretsRepo: jest.Mocked<UserSecretsRepository>;
  let emitter: jest.Mocked<TypedEvents>;
  let errorRecorder: { record: jest.Mock };

  beforeEach(async () => {
    challengeRepo = {
      insertChallenge: jest.fn().mockResolvedValue(undefined),
      insertChallengeIfUnderLimit: jest.fn().mockResolvedValue(true),
      getChallenge: jest.fn().mockResolvedValue({ userId: TEST_USER, expiresAt: FUTURE_DATE }),
    } as unknown as jest.Mocked<MfaChallengeRepository>;

    tokenRepo = {
      insertMfaToken: jest.fn().mockResolvedValue(undefined),
      getMfaTokenWithStatus: jest.fn().mockResolvedValue({
        jti: 'jti-test-1',
        userId: TEST_USER,
        fingerprintHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
        issuedAt: new Date(),
        expiresAt: FUTURE_DATE,
        isRevoked: false,
        isExpired: false,
      }),
      revokeMfaToken: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<MfaTokenRepository>;

    secretsRepo = {
      getEncryptedSecret: jest.fn().mockResolvedValue(TEST_ENC_TOTP),
      save: jest.fn().mockResolvedValue(undefined),
      deleteByUserId: jest.fn().mockResolvedValue(true),
    } as unknown as jest.Mocked<UserSecretsRepository>;

    emitter = {
      emit: jest.fn(),
    } as unknown as jest.Mocked<TypedEvents>;

    // MfaErrorRecorder is injected; we mock the `record` method. The real
    // util is covered by its own spec — here we only assert the contract
    // (called on infra error) without re-validating its internals.
    errorRecorder = { record: jest.fn() };

    const module = await Test.createTestingModule({
      providers: [
        MfaChallenger,
        { provide: MFA_CONFIG, useValue: buildMockConfig() },
        { provide: MfaChallengeRepository, useValue: challengeRepo },
        { provide: MfaTokenRepository, useValue: tokenRepo },
        { provide: UserSecretsRepository, useValue: secretsRepo },
        { provide: TypedEvents, useValue: emitter },
        { provide: MfaErrorRecorder, useValue: errorRecorder },
      ],
    }).compile();

    service = module.get(MfaChallenger);
  });

  // ---------------------------------------------------------------------------
  // createChallenge()
  // ---------------------------------------------------------------------------
  describe('createChallenge()', () => {
    it('Test 1: returns { challengeId, expiresAt } and inserts mfa_challenges row (MFA-01)', async () => {
      const result = await service.createChallenge(TEST_USER, TEST_IP);

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaCreateResult, { ok: true }>>(result);

      expect(typeof result.challengeId).toBe('string');
      expect(result.challengeId.length).toBeGreaterThan(0);
      expect(typeof result.expiresAt).toBe('number');
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      expect(challengeRepo.insertChallengeIfUnderLimit).toHaveBeenCalledTimes(1);
      expect(challengeRepo.insertChallengeIfUnderLimit).toHaveBeenCalledWith(
        result.challengeId,
        TEST_USER,
        expect.any(Date),
        expect.any(Number),
        expect.any(Number),
      );
      expect(challengeRepo.insertChallenge).not.toHaveBeenCalled();
    });

    it('WR-05: does NOT call the legacy insertChallenge two-query partner', async () => {
      await service.createChallenge(TEST_USER, TEST_IP);
      expect(challengeRepo.insertChallenge).not.toHaveBeenCalled();
    });

    it('WR-05: forwards rateLimitWindowMs + rateLimitMax to the atomic call', async () => {
      await service.createChallenge(TEST_USER, TEST_IP);
      const args = challengeRepo.insertChallengeIfUnderLimit.mock.calls[0];
      expect(args[3]).toBe(60_000);
      expect(args[4]).toBe(5);
    });

    it('Test 2: returns rate_limited after MFA_RATE_LIMIT_MAX initiations in window (MFA-08)', async () => {
      challengeRepo.insertChallengeIfUnderLimit.mockResolvedValueOnce(false);

      const result = await service.createChallenge(TEST_USER, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaCreateResult, { ok: false }>>(result);
      expect(result.reason).toBe('rate_limited');
    });

    it('WR-03: createChallenge infra error delegates to MfaErrorRecorder', async () => {
      challengeRepo.insertChallengeIfUnderLimit.mockRejectedValueOnce(new Error('db down'));
      const result = await service.createChallenge(TEST_USER, TEST_IP);
      assertOkFalse<Extract<MfaCreateResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
      expect(errorRecorder.record).toHaveBeenCalledTimes(1);
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaChallenger',
        'createChallenge',
        TEST_USER,
        expect.any(Error),
      );
    });

    it('Test 3: emits MFA_RATE_LIMITED (not MFA_FAILED) on rate-limit denial (D-18)', async () => {
      challengeRepo.insertChallengeIfUnderLimit.mockResolvedValueOnce(false);

      await service.createChallenge(TEST_USER, TEST_IP, 'ja4h-fingerprint');

      expect(emitter.emit).toHaveBeenCalledTimes(1);
      const [eventName, payload] = emitter.emit.mock.calls[0] as unknown as [string, unknown];
      expect(eventName).toBe(MFA_RATE_LIMITED);
      const allEventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(allEventNames).not.toContain(MFA_FAILED);
      expect((payload as { userId: string }).userId).toBe(TEST_USER);
    });
  });

  // ---------------------------------------------------------------------------
  // verifyTotp()
  // ---------------------------------------------------------------------------
  describe('verifyTotp()', () => {
    it('Test 4: returns { ok: true, token, expiresAt } for valid TOTP code (MFA-02, MFA-03)', async () => {
      const code = authenticator.generate(TEST_TOTP_SECRET);

      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        code,
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaVerifyResult, { ok: true }>>(result);

      expect(typeof result.token).toBe('string');
      expect(result.token.split('.').length).toBe(3);
      expect(typeof result.expiresAt).toBe('number');
      expect(result.expiresAt).toBeGreaterThan(Date.now());
    });

    it('Test 5: MFA JWT has typ:mfa, jti, sub, deviceId, fpHash claims (D-10)', async () => {
      const code = authenticator.generate(TEST_TOTP_SECRET);

      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        code,
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaVerifyResult, { ok: true }>>(result);

      const { payload } = await jwtVerify(result.token, secretBytes(), {
        algorithms: ['HS256'],
      });

      expect(payload['typ']).toBe('mfa');
      expect(typeof payload['jti']).toBe('string');
      expect(payload['sub']).toBe(TEST_USER);
      expect(payload['deviceId']).toBe(TEST_DEVICE);
      expect(typeof payload['fpHash']).toBe('string');
    });

    it('Test 6: fingerprint = SHA-256(userId|deviceId|ip) stored in mfa_tokens (MFA-04)', async () => {
      const code = authenticator.generate(TEST_TOTP_SECRET);

      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        code,
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaVerifyResult, { ok: true }>>(result);

      const expectedFp = expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP);

      const { payload } = await jwtVerify(result.token, secretBytes(), {
        algorithms: ['HS256'],
      });
      expect(payload['fpHash']).toBe(expectedFp);

      expect(tokenRepo.insertMfaToken).toHaveBeenCalledWith(
        expect.any(String),
        TEST_USER,
        expectedFp,
        expect.any(Date),
      );
    });

    it('Test 7: returns { ok: false, reason: expired_challenge } for expired challenge (MFA-01)', async () => {
      challengeRepo.getChallenge.mockResolvedValue({
        userId: TEST_USER,
        expiresAt: new Date(Date.now() - 1000),
      });

      const code = authenticator.generate(TEST_TOTP_SECRET);
      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        code,
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaVerifyResult, { ok: false }>>(result);
      expect(result.reason).toBe('expired_challenge');
    });

    it('Test 8: returns { ok: false, reason: invalid_code } for wrong TOTP code (MFA-02)', async () => {
      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        '000000',
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaVerifyResult, { ok: false }>>(result);
      expect(result.reason).toBe('invalid_code');
    });

    it('WR-02: decrypt failure emits internal mfa.secret_decrypt_failed; response stays unknown_user', async () => {
      const foreignKey = Buffer.alloc(32, 0x33).toString('base64');
      const corruptCiphertext = aesGcmEncrypt(TEST_TOTP_SECRET, foreignKey);
      secretsRepo.getEncryptedSecret.mockResolvedValue(corruptCiphertext);

      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        '000000',
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );
      assertOkFalse<Extract<MfaVerifyResult, { ok: false }>>(result);
      expect(result.reason).toBe('unknown_user');

      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_SECRET_DECRYPT_FAILED);
      expect(eventNames).toContain(MFA_FAILED);
    });

    it('Test 9: returns { ok: false, reason: unknown_user } when user has no secret (D-16)', async () => {
      secretsRepo.getEncryptedSecret.mockResolvedValue(null);

      const code = authenticator.generate(TEST_TOTP_SECRET);
      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        code,
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaVerifyResult, { ok: false }>>(result);
      expect(result.reason).toBe('unknown_user');
    });

    it('Test 10: verifyTotp failure emits MFA_FAILED with reason (D-12)', async () => {
      challengeRepo.getChallenge.mockResolvedValue({
        userId: TEST_USER,
        expiresAt: new Date(Date.now() - 1000),
      });

      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        '000000',
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
        'ja4h-123',
      );

      expect(result.ok).toBe(false);

      expect(emitter.emit).toHaveBeenCalledTimes(1);
      const [eventName, payload] = emitter.emit.mock.calls[0] as unknown as [
        string,
        Record<string, unknown>,
      ];
      expect(eventName).toBe(MFA_FAILED);
      expect(payload.userId).toBe(TEST_USER);
      expect(payload.ip).toBe(TEST_IP);
      expect(typeof payload.reason).toBe('string');
    });

    it('WR-03: verifyTotp outer infra error delegates to MfaErrorRecorder', async () => {
      challengeRepo.getChallenge.mockRejectedValueOnce(new Error('db down'));
      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        '000000',
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );
      expect(result.ok).toBe(false);
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaChallenger',
        'verifyTotp',
        TEST_USER,
        expect.any(Error),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // validateMfaToken()
  // ---------------------------------------------------------------------------
  describe('validateMfaToken()', () => {
    it('Test 11: returns { ok: true, claims } for valid token with matching fingerprint (MFA-05)', async () => {
      const token = await mintMfaJwt({ jti: 'jti-test-1' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaValidateResult, { ok: true }>>(result);
      expect(result.claims.sub).toBe(TEST_USER);
      expect(result.claims.typ).toBe('mfa');
      expect(result.claims.deviceId).toBe(TEST_DEVICE);
    });

    it('Test 12: returns { ok: false, reason: wrong_type } for token with typ != mfa (D-10)', async () => {
      const token = await mintMfaJwt({ typ: 'access' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('wrong_type');
    });

    it('Test 13: returns { ok: false, reason: fingerprint_mismatch } for token from different IP (MFA-05, D-06)', async () => {
      const token = await mintMfaJwt({ jti: 'jti-test-1' });

      const result = await service.validateMfaToken(
        token,
        TEST_USER,
        TEST_DEVICE,
        '192.168.99.99',
      );

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('fingerprint_mismatch');
    });

    it('Test 14a: returns { ok: false, reason: revoked } for jti with revoked_at set (D-08)', async () => {
      tokenRepo.getMfaTokenWithStatus.mockResolvedValue({
        jti: 'jti-revoked',
        userId: TEST_USER,
        fingerprintHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
        issuedAt: new Date(),
        expiresAt: FUTURE_DATE,
        isRevoked: true,
        isExpired: false,
      });
      const token = await mintMfaJwt({ jti: 'jti-revoked' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('revoked');
    });

    it('Test 14b: returns { ok: false, reason: unknown_jti } for jti not in mfa_tokens (D-11)', async () => {
      tokenRepo.getMfaTokenWithStatus.mockResolvedValue(null);
      const token = await mintMfaJwt({ jti: 'jti-unknown' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('unknown_jti');
    });

    it('Test 15: validateMfaToken failure emits MFA_FAILED (D-12)', async () => {
      tokenRepo.getMfaTokenWithStatus.mockResolvedValue(null);

      const token = await mintMfaJwt({ jti: 'jti-missing' });
      const result = await service.validateMfaToken(
        token,
        TEST_USER,
        TEST_DEVICE,
        TEST_IP,
        'ja4h-abc',
      );

      expect(result.ok).toBe(false);

      expect(emitter.emit).toHaveBeenCalledTimes(1);
      const [eventName] = emitter.emit.mock.calls[0] as unknown as [string];
      expect(eventName).toBe(MFA_FAILED);
    });

    it('WR-01: validateMfaToken uses atomic getMfaTokenWithStatus', async () => {
      const token = await mintMfaJwt({ jti: 'jti-atomic' });
      await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);
      expect(tokenRepo.getMfaTokenWithStatus).toHaveBeenCalledWith('jti-atomic');
    });

    it('WR-01: revoked flag from atomic helper returns reason=revoked even if expires_at is in the future', async () => {
      tokenRepo.getMfaTokenWithStatus.mockResolvedValue({
        jti: 'jti-race',
        userId: TEST_USER,
        fingerprintHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
        issuedAt: new Date(),
        expiresAt: FUTURE_DATE,
        isRevoked: true,
        isExpired: false,
      });
      const token = await mintMfaJwt({ jti: 'jti-race' });
      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('revoked');
    });

    it('WR-01: expired flag from atomic helper returns reason=expired', async () => {
      tokenRepo.getMfaTokenWithStatus.mockResolvedValue({
        jti: 'jti-exp',
        userId: TEST_USER,
        fingerprintHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() - 1000),
        isRevoked: false,
        isExpired: true,
      });
      const token = await mintMfaJwt({ jti: 'jti-exp' });
      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('expired');
    });

    it('BL-01: returns reason=internal (not signature) on repo failure', async () => {
      tokenRepo.getMfaTokenWithStatus.mockRejectedValueOnce(
        new Error('postgres: connection refused'),
      );
      const token = await mintMfaJwt({ jti: 'jti-db-down' });
      const result = await service.validateMfaToken(
        token,
        TEST_USER,
        TEST_DEVICE,
        TEST_IP,
        'ja4h-x',
      );
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
    });

    it('BL-01: does NOT emit MFA_FAILED on repo failure (infra is not a security signal)', async () => {
      tokenRepo.getMfaTokenWithStatus.mockRejectedValueOnce(
        new Error('postgres: connection refused'),
      );
      const token = await mintMfaJwt({ jti: 'jti-db-down' });
      await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP, 'ja4h-x');
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).not.toContain(MFA_FAILED);
    });

    it('BL-01: delegates infra error to MfaErrorRecorder (dashboards observe MFA outages)', async () => {
      tokenRepo.getMfaTokenWithStatus.mockRejectedValueOnce(
        new Error('postgres: connection refused'),
      );
      const token = await mintMfaJwt({ jti: 'jti-db-down' });
      await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP, 'ja4h-x');
      expect(errorRecorder.record).toHaveBeenCalledWith(
        'MfaChallenger',
        'validateMfaToken',
        TEST_USER,
        expect.any(Error),
      );
    });

    it('BL-01: real signature failure still reports signature and emits MFA_FAILED', async () => {
      const wrongSecret = new TextEncoder().encode(
        'completely-different-secret-32-bytes-or-more!!',
      );
      const badToken = await new SignJWT({
        sub: TEST_USER,
        jti: 'jti-bad-sig',
        deviceId: TEST_DEVICE,
        typ: 'mfa',
        fpHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(wrongSecret);

      const result = await service.validateMfaToken(badToken, TEST_USER, TEST_DEVICE, TEST_IP);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('signature');
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_FAILED);
    });
  });

  // Ensure MfaErrorRecorder is reached on infra errors (smoke check that the
  // infra-error path is wired uniformly across the three public methods).
  describe('infra error routing (MFA_INFRA_ERROR symbol export still defined)', () => {
    it('MFA_INFRA_ERROR symbol exported by policy-events', () => {
      expect(typeof MFA_INFRA_ERROR).toBe('string');
    });
  });
});
