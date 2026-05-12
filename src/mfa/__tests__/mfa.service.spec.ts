/**
 * Phase 7 — MfaService unit tests (MFA-01..MFA-08, D-05..D-18)
 * TDD: tests written first; Wave 2 (07-02) fills in the implementation.
 * All repository + EventEmitter2 dependencies are mocked — no Postgres / network.
 */
import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { totp as authenticator } from '../../shared/totp.util';
import { Test } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { MfaService, MfaCreateResult, MfaVerifyResult, MfaValidateResult } from '../mfa.service';
import type { MfaEnrollResult, MfaConfirmResult, MfaDeleteEnrollmentResult } from '../mfa.service';
import { MfaChallengeRepository } from '../repositories/mfa-challenge.repository';
import { MfaTokenRepository } from '../repositories/mfa-token.repository';
import { UserSecretsRepository } from '../repositories/user-secrets.repository';
import { AppConfigService } from '../../config/config.service';
import { aesGcmEncrypt, aesGcmDecrypt } from '../../shared/aes-gcm.util';
import {
  MFA_FAILED,
  MFA_INFRA_ERROR,
  MFA_RATE_LIMITED,
  MFA_SECRET_DECRYPT_FAILED,
} from '../../policy/policy-events';

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
    // Phase 11
    mfaIssuerName: 'Test-Issuer',
    mfaEnrollPendingTtlMs: 600_000,
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
  let pendingStore: {
    set: jest.Mock;
    get: jest.Mock;
    delete: jest.Mock;
    size: jest.Mock;
    clear: jest.Mock;
    hasPendingForUser: jest.Mock;
    incrementAttempts: jest.Mock;
  };

  // PendingEnrollmentStore is provided in Plan 11-01. Use a deferred require for Wave 0.
  let PendingEnrollmentStore: unknown;
  try {
    PendingEnrollmentStore = require('../enrollment.store').PendingEnrollmentStore;
  } catch {
    PendingEnrollmentStore = class {};
  }

  beforeEach(async () => {
    challengeRepo = {
      insertChallenge: jest.fn().mockResolvedValue(undefined),
      // WR-05 (phase 14): atomic conditional insert. Default to success (true).
      insertChallengeIfUnderLimit: jest.fn().mockResolvedValue(true),
      getChallenge: jest.fn().mockResolvedValue({ userId: TEST_USER, expiresAt: FUTURE_DATE }),
    } as unknown as jest.Mocked<MfaChallengeRepository>;

    tokenRepo = {
      insertMfaToken: jest.fn().mockResolvedValue(undefined),
      // WR-01 (phase 14): validateMfaToken now uses the atomic helper.
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
    } as unknown as jest.Mocked<EventEmitter2>;

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
        MfaService,
        { provide: AppConfigService, useValue: buildMockConfig() },
        { provide: MfaChallengeRepository, useValue: challengeRepo },
        { provide: MfaTokenRepository, useValue: tokenRepo },
        { provide: UserSecretsRepository, useValue: secretsRepo },
        { provide: EventEmitter2, useValue: emitter },
        { provide: PendingEnrollmentStore as never, useValue: pendingStore },
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

      // WR-05: atomic conditional insert is the hot path. Legacy
      // insertChallenge is not called by the service.
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

    // WR-05 (phase 14): atomic conditional insert closes count+insert TOCTOU.
    // IN-02 (phase 14, iter3): countRecentChallenges has been deleted; the
    // legacy insertChallenge sibling must still not be the hot path.
    it('WR-05: does NOT call the legacy insertChallenge two-query partner', async () => {
      await service.createChallenge(TEST_USER, TEST_IP);
      expect(challengeRepo.insertChallenge).not.toHaveBeenCalled();
    });

    it('WR-05: forwards rateLimitWindowMs + rateLimitMax to the atomic call', async () => {
      await service.createChallenge(TEST_USER, TEST_IP);
      const args = challengeRepo.insertChallengeIfUnderLimit.mock.calls[0];
      // args order: id, userId, expiresAt, windowMs, maxCount
      expect(args[3]).toBe(60_000); // mfaRateLimitWindowMs from buildMockConfig
      expect(args[4]).toBe(5); // mfaRateLimitMax from buildMockConfig
    });

    it('Test 2: returns rate_limited after MFA_RATE_LIMIT_MAX initiations in window (MFA-08)', async () => {
      // WR-05: rate-limit denial is now expressed as a false return from the
      // atomic conditional insert (predicate failed at write time).
      challengeRepo.insertChallengeIfUnderLimit.mockResolvedValueOnce(false);

      const result = await service.createChallenge(TEST_USER, TEST_IP);

      expect(result.ok).toBe(false);
      assertOkFalse<Extract<MfaCreateResult, { ok: false }>>(result);
      expect(result.reason).toBe('rate_limited');
    });

    // WR-03 (phase 14): silent infra errors used to return { ok: false,
    // reason: 'internal' } with no log, no event, no audit. Threat escalation
    // could not fire. Every catch site must log error + emit mfa.infra_error.
    it('WR-03: createChallenge infra error logs + emits mfa.infra_error', async () => {
      challengeRepo.insertChallengeIfUnderLimit.mockRejectedValueOnce(new Error('db down'));
      const result = await service.createChallenge(TEST_USER, TEST_IP);
      assertOkFalse<Extract<MfaCreateResult, { ok: false }>>(result);
      expect(result.reason).toBe('internal');
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });

    it('Test 3: emits MFA_RATE_LIMITED (not MFA_FAILED) on rate-limit denial (D-18)', async () => {
      challengeRepo.insertChallengeIfUnderLimit.mockResolvedValueOnce(false);

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

    // WR-02 (phase 14): preserve enumeration-resistant response but emit an
    // internal-only signal so ops dashboards can alert on a spike of decrypt
    // failures (e.g., botched MFA_TOTP_ENCRYPTION_KEY rotation).
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
      // Threat ladder still observes MFA_FAILED with reason='unknown_user'.
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
      const [eventName] = emitter.emit.mock.calls[0] as [string];
      expect(eventName).toBe(MFA_FAILED);
    });

    // WR-01 (phase 14): validateMfaToken must use a single atomic SELECT to
    // close the revocation TOCTOU window. IN-03 (iter3): the legacy two-query
    // helpers (getMfaToken / getMfaTokenStatus) were deleted; the assertion
    // here is now only that the atomic helper is called with the jti.
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

    // BL-01 (phase 14): Outer catch must report DB / repo errors as 'internal'
    // and MUST NOT emit MFA_FAILED — otherwise ThreatEscalationService
    // .onMfaFailed counts every Postgres blip as a tampering signal.
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

    it('BL-01: emits mfa.infra_error so dashboards can detect MFA outages', async () => {
      tokenRepo.getMfaTokenWithStatus.mockRejectedValueOnce(
        new Error('postgres: connection refused'),
      );
      const token = await mintMfaJwt({ jti: 'jti-db-down' });
      await service.validateMfaToken(token, TEST_USER, TEST_DEVICE, TEST_IP, 'ja4h-x');
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });

    it('BL-01: real signature failure still reports signature and emits MFA_FAILED', async () => {
      // Forge a token with the WRONG secret so jwtVerify rejects it inside the
      // inner try, NOT the outer catch.
      const wrongSecret = new TextEncoder().encode(
        'completely-different-secret-32-bytes-or-more!!',
      );
      const badToken = await new SignJWT({
        sub: TEST_USER,
        jti: 'jti-bad-sig',
        deviceId: TEST_DEVICE,
        typ: 'mfa',
        fpHash: expectedFingerprint(TEST_USER, TEST_DEVICE, TEST_IP),
      } as Record<string, unknown>)
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

  // -------------------------------------------------------------------------
  // createEnrollment() — Phase 11
  // -------------------------------------------------------------------------
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
      const result = await service.createEnrollment(TEST_USER /* no email */);
      assertOkTrue<Extract<MfaEnrollResult, { ok: true }>>(result);
      expect(result.otpauthUri).toContain(`Test-Issuer:${TEST_USER}`);
      expect(result.otpauthUri).not.toContain('undefined');
    });

    it('ENROLL-03: returns { ok: false, reason: already_enrolled } when user_secrets row exists', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockResolvedValue(TEST_ENC_TOTP); // existing row
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

    // WR-03 (phase 14)
    it('WR-03: createEnrollment infra error emits mfa.infra_error', async () => {
      secretsRepo.getEncryptedSecret = jest.fn().mockRejectedValue(new Error('db down'));
      await service.createEnrollment(TEST_USER, 'alice@example.com');
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });
  });

  // -------------------------------------------------------------------------
  // confirmEnrollment() — Phase 11
  // -------------------------------------------------------------------------
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
      // Round-trip: decrypt should match the pending secret
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

    // BL-02 (phase 14): close silent TOTP brute-force window during enrollment.
    it('BL-02: emits MFA_FAILED on invalid TOTP during enrollment', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed!.p as { reason: string }).reason).toBe('invalid_totp_enrollment');
      expect((failed!.p as { userId: string }).userId).toBe(TEST_USER);
    });

    it('BL-02: increments the per-enrollmentId attempt counter on each failure', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      expect(pendingStore.incrementAttempts).toHaveBeenCalledWith(ENROLL_ID);
    });

    it('BL-02: on attempts >= ENROLL_MAX_ATTEMPTS deletes pending and emits MFA_RATE_LIMITED', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaService.ENROLL_MAX_ATTEMPTS);
      const result = await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      assertOkFalse<Extract<MfaConfirmResult, { ok: false }>>(result);
      expect(result.reason).toBe('invalid_totp');
      expect(pendingStore.delete).toHaveBeenCalledWith(ENROLL_ID);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_RATE_LIMITED);
    });

    it('BL-02: under the attempt cap does NOT emit MFA_RATE_LIMITED', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaService.ENROLL_MAX_ATTEMPTS - 1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).not.toContain(MFA_RATE_LIMITED);
      expect(pendingStore.delete).not.toHaveBeenCalled();
    });

    // IN-04 (phase 14, iter3): confirmEnrollment must propagate ip + ja4h into
    // both the MFA_FAILED { invalid_totp_enrollment } and the
    // MFA_RATE_LIMITED { enrollment_attempts_exhausted } payloads so
    // ThreatEscalationService and downstream IP-bound rate limiters can
    // correlate the enrollment brute-force to a network identity (parity with
    // verifyTotp / createChallenge).
    it('IN-04: MFA_FAILED on invalid enrollment TOTP carries ip + ja4h', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP, 'ja4h-enroll-1');
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed!.p as { ip: string }).ip).toBe(TEST_IP);
      expect((failed!.p as { ja4h?: string }).ja4h).toBe('ja4h-enroll-1');
    });

    it('IN-04: MFA_RATE_LIMITED on attempts exhausted carries ip + ja4h', async () => {
      pendingStore.incrementAttempts.mockReturnValue(MfaService.ENROLL_MAX_ATTEMPTS);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP, 'ja4h-enroll-2');
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const rateLimited = calls.find((c) => c.name === MFA_RATE_LIMITED);
      expect(rateLimited).toBeDefined();
      expect((rateLimited!.p as { ip: string }).ip).toBe(TEST_IP);
      expect((rateLimited!.p as { ja4h?: string }).ja4h).toBe('ja4h-enroll-2');
    });

    it('IN-04: omits ja4h key when caller does not supply it', async () => {
      pendingStore.incrementAttempts.mockReturnValue(1);
      await service.confirmEnrollment(ENROLL_ID, '000000', TEST_USER, TEST_IP);
      const calls = emitter.emit.mock.calls.map(([name, p]) => ({ name, p }));
      const failed = calls.find((c) => c.name === MFA_FAILED);
      expect(failed).toBeDefined();
      expect((failed!.p as { ip: string }).ip).toBe(TEST_IP);
      expect((failed!.p as { ja4h?: string }).ja4h).toBeUndefined();
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

    // WR-03 (phase 14)
    it('WR-03: confirmEnrollment infra error emits mfa.infra_error', async () => {
      (secretsRepo.save as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      await service.confirmEnrollment(ENROLL_ID, validCode(), TEST_USER);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });
  });

  // -------------------------------------------------------------------------
  // deleteEnrollment() — Phase 11 admin reset
  // -------------------------------------------------------------------------
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

    // WR-03 (phase 14)
    it('WR-03: deleteEnrollment infra error emits mfa.infra_error', async () => {
      (secretsRepo.deleteByUserId as jest.Mock).mockRejectedValueOnce(new Error('db down'));
      await service.deleteEnrollment(TEST_USER);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });
  });

  // WR-03 (phase 14): verifyTotp outer-catch infra error also routes through
  // recordInfraError so dashboards observe verify-time DB outages.
  describe('verifyTotp() infra observability (WR-03)', () => {
    it('verifyTotp outer infra error emits mfa.infra_error', async () => {
      challengeRepo.getChallenge.mockRejectedValueOnce(new Error('db down'));
      const result = await service.verifyTotp(
        TEST_CHALLENGE_ID,
        '000000',
        TEST_USER,
        TEST_IP,
        TEST_DEVICE,
      );
      expect(result.ok).toBe(false);
      const eventNames = emitter.emit.mock.calls.map(([name]) => name);
      expect(eventNames).toContain(MFA_INFRA_ERROR);
    });
  });

  // WR-NEW-01 (phase 14, iter2): recordInfraError must pass the Error's
  // stack-frame list (string) to Logger.error as the 2nd argument so the
  // NestJS Logger preserves the full stack trace in structured output.
  // The previous implementation passed the Error instance directly, which
  // NestJS stringifies via String(err) — collapsing to "Error: <msg>" and
  // dropping every stack frame. This regression undermines the WR-03 goal
  // of improving incident-triage observability for swallowed infra errors.
  describe('recordInfraError() Logger.error signature (WR-NEW-01)', () => {
    it('passes the Error stack string (not the Error instance) to Logger.error', async () => {
      const errSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
      try {
        const boom = new Error('db down');
        // Ensure a deterministic stack frame for the assertion.
        boom.stack = 'Error: db down\n    at frame-1\n    at frame-2';
        challengeRepo.insertChallengeIfUnderLimit.mockRejectedValueOnce(boom);

        await service.createChallenge(TEST_USER, TEST_IP);

        expect(errSpy).toHaveBeenCalled();
        const [message, stack] = errSpy.mock.calls[errSpy.mock.calls.length - 1] as [
          unknown,
          unknown,
        ];
        // Message string includes op + the Error message.
        expect(typeof message).toBe('string');
        expect(message).toEqual(expect.stringContaining('createChallenge'));
        expect(message).toEqual(expect.stringContaining('db down'));
        // Stack must be a string (not an Error instance) containing frames.
        expect(typeof stack).toBe('string');
        expect(stack).toEqual(expect.stringContaining('frame-1'));
        expect(stack).not.toBeInstanceOf(Error);
      } finally {
        errSpy.mockRestore();
      }
    });

    it('wraps non-Error throwables and still passes a string stack', async () => {
      const errSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
      try {
        // Reject with a non-Error value to exercise the wrap branch.
        challengeRepo.insertChallengeIfUnderLimit.mockRejectedValueOnce('plain-string-error');

        await service.createChallenge(TEST_USER, TEST_IP);

        expect(errSpy).toHaveBeenCalled();
        const [message, stack] = errSpy.mock.calls[errSpy.mock.calls.length - 1] as [
          unknown,
          unknown,
        ];
        expect(typeof message).toBe('string');
        expect(message).toEqual(expect.stringContaining('plain-string-error'));
        expect(typeof stack).toBe('string');
      } finally {
        errSpy.mockRestore();
      }
    });
  });
});
