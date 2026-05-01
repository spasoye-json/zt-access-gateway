/**
 * Phase 7 — MfaService unit tests (MFA-01..MFA-08, D-05..D-18)
 * TDD: tests written first; Wave 2 (07-02) fills in the implementation.
 * All repository + EventEmitter2 dependencies are mocked — no Postgres / network.
 */
import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { authenticator } from '@otplib/v12-adapter';
import { Test } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';

import {
  MfaService,
  MfaCreateResult,
  MfaVerifyResult,
  MfaValidateResult,
} from '../mfa.service';
import { MfaChallengeRepository } from '../repositories/mfa-challenge.repository';
import { MfaTokenRepository } from '../repositories/mfa-token.repository';
import { UserSecretsRepository } from '../repositories/user-secrets.repository';
import { AppConfigService } from '../../config/config.service';
import { aesGcmEncrypt } from '../../shared/aes-gcm.util';
import { MFA_FAILED, MFA_RATE_LIMITED } from '../../policy/policy-events';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------
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

function buildMockConfig(): Partial<AppConfigService> {
  return {
    mfaJwtSecret: TEST_JWT_SECRET,
    mfaTotpEncryptionKey: TEST_ENC_KEY,
    mfaChallengeTtlMs: 300_000,
    mfaTokenTtlMs: 600_000,
    mfaRateLimitMax: 5,
    mfaRateLimitWindowMs: 60_000,
  };
}

/**
 * Signs an MFA JWT using the TEST_JWT_SECRET.
 * `typ` lets tests forge a token with a wrong typ claim.
 */
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
  return new SignJWT({ sub: userId, jti, deviceId, fpHash, typ } as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(secretBytes());
}

// Helper type narrowers
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

// ---------------------------------------------------------------------------
// describe('MfaService')
// ---------------------------------------------------------------------------
describe('MfaService', () => {
  let service: MfaService;
  let challengeRepo: jest.Mocked<MfaChallengeRepository>;
  let tokenRepo: jest.Mocked<MfaTokenRepository>;
  let secretsRepo: jest.Mocked<UserSecretsRepository>;
  let emitter: jest.Mocked<EventEmitter2>;

  beforeEach(async () => {
    challengeRepo = {
      countRecentChallenges: jest.fn().mockResolvedValue(0),
      insertChallenge: jest.fn().mockResolvedValue(undefined),
      getChallenge: jest.fn().mockResolvedValue({ userId: TEST_USER, expiresAt: FUTURE_DATE }),
    } as unknown as jest.Mocked<MfaChallengeRepository>;

    tokenRepo = {
      insertMfaToken: jest.fn().mockResolvedValue(undefined),
      getMfaToken: jest.fn().mockResolvedValue({
        jti: 'jti-test-1',
        userId: TEST_USER,
        fingerprintHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
        issuedAt: new Date(),
        expiresAt: FUTURE_DATE,
      }),
      getMfaTokenStatus: jest.fn().mockResolvedValue({ isRevoked: false, isExpired: false }),
      revokeMfaToken: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<MfaTokenRepository>;

    secretsRepo = {
      getEncryptedSecret: jest.fn().mockResolvedValue(TEST_ENC_TOTP),
    } as unknown as jest.Mocked<UserSecretsRepository>;

    emitter = {
      emit: jest.fn(),
    } as unknown as jest.Mocked<EventEmitter2>;

    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: AppConfigService, useValue: buildMockConfig() },
        { provide: MfaChallengeRepository, useValue: challengeRepo },
        { provide: MfaTokenRepository, useValue: tokenRepo },
        { provide: UserSecretsRepository, useValue: secretsRepo },
        { provide: EventEmitter2, useValue: emitter },
      ],
    }).compile();

    service = module.get(MfaService);
  });

  // -------------------------------------------------------------------------
  // createChallenge()
  // -------------------------------------------------------------------------
  describe('createChallenge()', () => {
    it('Test 1: returns { challengeId, expiresAt } and inserts mfa_challenges row (MFA-01)', async () => {
      const result = await service.createChallenge(TEST_USER, TEST_IP);

      expect(result.ok).toBe(true);
      assertOkTrue<Extract<MfaCreateResult, { ok: true }>>(result);

      expect(typeof result.challengeId).toBe('string');
      expect(result.challengeId.length).toBeGreaterThan(0);
      expect(typeof result.expiresAt).toBe('number');
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      expect(challengeRepo.insertChallenge).toHaveBeenCalledTimes(1);
      expect(challengeRepo.insertChallenge).toHaveBeenCalledWith(
        result.challengeId,
        TEST_USER,
        expect.any(Date),
      );
    });

    it('Test 2: returns rate_limited after MFA_RATE_LIMIT_MAX initiations in window (MFA-08)', async () => {
      challengeRepo.countRecentChallenges.mockResolvedValue(5);

      const result = await service.createChallenge(TEST_USER, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaCreateResult, { ok: false }>>(result);
      expect(result.reason).toBe('rate_limited');

      expect(challengeRepo.insertChallenge).not.toHaveBeenCalled();
    });

    it('Test 3: emits MFA_RATE_LIMITED (not MFA_FAILED) on rate-limit denial (D-18)', async () => {
      challengeRepo.countRecentChallenges.mockResolvedValue(5);

      await service.createChallenge(TEST_USER, TEST_IP, 'ja4h-fingerprint');

      expect(emitter.emit).toHaveBeenCalledTimes(1);
      const [eventName, payload] = emitter.emit.mock.calls[0] as [string, unknown];
      expect(eventName).toBe(MFA_RATE_LIMITED);
      const allEventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(allEventNames).not.toContain(MFA_FAILED);
      expect((payload as { userId: string }).userId).toBe(TEST_USER);
    });
  });

  // -------------------------------------------------------------------------
  // verifyTotp()
  // -------------------------------------------------------------------------
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
      const [eventName, payload] = emitter.emit.mock.calls[0] as [string, Record<string, unknown>];
      expect(eventName).toBe(MFA_FAILED);
      expect(payload.userId).toBe(TEST_USER);
      expect(payload.ip).toBe(TEST_IP);
      expect(typeof payload.reason).toBe('string');
    });
  });

  // -------------------------------------------------------------------------
  // validateMfaToken()
  // -------------------------------------------------------------------------
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
        '192.168.99.99', // different IP
      );

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('fingerprint_mismatch');
    });

    it('Test 14a: returns { ok: false, reason: revoked } for jti with revoked_at set (D-08)', async () => {
      tokenRepo.getMfaTokenStatus.mockResolvedValue({ isRevoked: true, isExpired: false });
      const token = await mintMfaJwt({ jti: 'jti-revoked' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('revoked');
    });

    it('Test 14b: returns { ok: false, reason: unknown_jti } for jti not in mfa_tokens (D-11)', async () => {
      tokenRepo.getMfaTokenStatus.mockResolvedValue(null);
      const token = await mintMfaJwt({ jti: 'jti-unknown' });

      const result = await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaValidateResult, { ok: false }>>(result);
      expect(result.reason).toBe('unknown_jti');
    });

    it('Test 15: validateMfaToken failure emits MFA_FAILED (D-12)', async () => {
      tokenRepo.getMfaTokenStatus.mockResolvedValue(null);

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
      const [eventName] = emitter.emit.mock.calls[0] as [string];
      expect(eventName).toBe(MFA_FAILED);
    });
  });
});
