/**
 * Phase 14 Plan 02 — closes v1.0 milestone audit Item 10.
 *
 * SC-2: drives evaluateScore > hashcashTriggerThreshold through the live
 * AppModule and asserts the 429 + X-Hashcash-Challenge + Retry-After round-trip.
 *
 * Overrides TrustScoreService (deterministic score), ProxyService (avoids
 * real mTLS to a downstream), and PolicyEvaluatorService (deviation Rule 3
 * — under NestJS forRoutes('*') middleware nesting `req.path === '/'` so the
 * real Casbin policy DENIES any /users/* request the spec issues; overriding
 * to ALLOW isolates the hashcash step 8 codepath). Everything else — Auth,
 * JWT validation, HashcashService (issueChallenge + verifySolution +
 * UsedNonceStore), GatewayMiddleware step 8 — runs LIVE.
 *
 * Difficulty pinned to 4 via env so the PoW solve in Test 3 is deterministic
 * (~16 iterations, <1ms). Threshold pinned to 0.7 for clarity.
 *
 * Predecessor `src/hashcash/__tests__/hashcash.e2e.spec.ts` is describe.skip'd
 * (file-header comment explains the Phase 10 D-02 migration). This spec is the
 * canonical post-migration coverage and the proof site for SC-2.
 */

// Env vars set BEFORE any NestJS module import — ConfigModule validates at decoration time.
process.env.NODE_ENV = 'test';
process.env.HASHCASH_HMAC_SECRET = process.env.HASHCASH_HMAC_SECRET ?? 'a'.repeat(64);
process.env.HASHCASH_DIFFICULTY_MIN = '4';
process.env.HASHCASH_DIFFICULTY_MAX = '4';
process.env.HASHCASH_TRIGGER_THRESHOLD = '0.7';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret-that-is-at-least-32-chars-long!';
if (!process.env.MTLS_CA_CERT_PATH) process.env.MTLS_CA_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_CERT_PATH) process.env.MTLS_CLIENT_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_KEY_PATH) process.env.MTLS_CLIENT_KEY_PATH = '/dev/null';
if (!process.env.MTLS_ALLOWED_SUBJECTS) process.env.MTLS_ALLOWED_SUBJECTS = 'cn=test';
if (!process.env.DATABASE_URL)
  process.env.DATABASE_URL = 'postgresql://fake:fake@localhost:5432/fake-test-db';
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-test-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({
    users: 'https://users.test:8443',
  });

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';
import { ProxyService } from '../../src/proxy/proxy.service';
import { AuditRepository } from '../../src/audit/audit.repository';
import { TrustScoreService } from '../../src/trust-score/trust-score.service';
import { PolicyEvaluatorService } from '../../src/policy/policy-evaluator.service';
import { FingerprintStore } from '../../src/fingerprint/fingerprint.store';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';
import { hashSolution, countLeadingZeroBits } from '../../src/hashcash/hashcash.util';

function solvePoW(nonce: string, difficulty: number): string {
  for (let i = 0; ; i++) {
    const sol = i.toString(36);
    if (countLeadingZeroBits(hashSolution(nonce, sol)) >= difficulty) return sol;
  }
}

describe('Phase 14 Plan 02 — Hashcash 429 round-trip e2e (SC-2)', () => {
  let app: INestApplication;
  const fakeProxy = {
    forward: jest.fn(),
    onModuleInit: jest.fn(),
  };
  const fakeAudit = {
    insert: jest.fn().mockResolvedValue(undefined),
    findLogs: jest.fn().mockResolvedValue({ items: [], total: 0 }),
    onModuleDestroy: jest.fn(),
  };
  const fakeTrustScore = {
    evaluateScore: jest.fn(),
    recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
  };
  // Deviation Rule 3 (blocking): real PolicyEvaluatorService sees req.path === '/'
  // under NestJS forRoutes('*') middleware nesting (see GatewayMiddleware lines
  // 71-81) and DENYs because policy.csv has no rule for `role:user, /`. Override
  // to ALLOW so the test isolates the hashcash step 8 codepath. Mirrors the
  // override pattern in tests/integration/gateway.e2e-spec.ts lines 81-86.
  const fakePolicy = {
    evaluate: jest.fn(),
    onModuleInit: jest.fn(),
    addRule: jest.fn(),
    removeRule: jest.fn(),
  };

  let token: string;
  let jtiCounter = 0;
  const uniqueJti = (label: string): string =>
    `hcsh-${label}-${Date.now()}-${++jtiCounter}-${Math.random().toString(36).slice(2, 8)}`;

  // Unique per-test userId+deviceId so HashcashService.issueChallenge produces
  // a distinct nonce each test (nonce is derived from (sub, dev, score, iat-sec)
  // — consecutive tests within the same second otherwise yield the same nonce,
  // causing UsedNonceStore replay collisions across tests).
  let testCounter = 0;
  let testUserId = 'user-1';
  let testDeviceId = 'device-1';

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(ProxyService)
      .useValue(fakeProxy)
      .overrideProvider(AuditRepository)
      .useValue(fakeAudit)
      .overrideProvider(TrustScoreService)
      .useValue(fakeTrustScore)
      .overrideProvider(PolicyEvaluatorService)
      .useValue(fakePolicy)
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    fakeProxy.forward.mockResolvedValue({
      status: 200,
      data: { id: 'u-1' },
    });
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    fakeProxy.forward.mockResolvedValue({ status: 200, data: { id: 'u-1' } });
    fakeAudit.insert.mockResolvedValue(undefined);
    fakePolicy.evaluate.mockResolvedValue({
      decision: 'ALLOW',
      reason: 'score_below_challenge_threshold',
      score: 0.1,
      matchedSubject: 'role:user',
    });
    app.get(FingerprintStore).clear();
    testCounter++;
    testUserId = `user-${testCounter}`;
    testDeviceId = `device-${testCounter}`;
    token = await createHs256Token(
      { sub: testUserId, roles: ['user'], deviceId: testDeviceId },
      { jti: uniqueJti('round-trip') },
    );
  });

  it('low score (< 0.7) → 200, no challenge headers (baseline)', async () => {
    fakeTrustScore.evaluateScore.mockResolvedValue(0.5);

    const res = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.headers['x-hashcash-challenge']).toBeUndefined();
    expect(res.headers['retry-after']).toBeUndefined();
  });

  it('SC-2: high score (> 0.7) + no PoW headers → 429 + X-Hashcash-Challenge + Retry-After', async () => {
    fakeTrustScore.evaluateScore.mockResolvedValue(0.85);

    const res = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(429);
    expect(res.headers['x-hashcash-challenge']).toBeDefined();
    expect(res.headers['retry-after']).toBe('1');

    const challenge = res.headers['x-hashcash-challenge'];
    const lastColon = challenge.lastIndexOf(':');
    const nonce = challenge.slice(0, lastColon);
    const difficulty = parseInt(challenge.slice(lastColon + 1), 10);
    expect(difficulty).toBe(4);
    expect(nonce.length).toBeGreaterThan(0);
    expect(res.body).toMatchObject({
      error: 'proof_of_work_required',
      nonce,
      difficulty: 4,
    });
    expect(typeof res.body.expiresAt).toBe('number');
    expect(typeof res.body.requestId).toBe('string');
    // Proxy NOT called — request blocked at step 8
    expect(fakeProxy.forward).not.toHaveBeenCalled();
  });

  it('high score + solved PoW → 200 (proxy reached after verify)', async () => {
    fakeTrustScore.evaluateScore.mockResolvedValue(0.85);

    // Step 1: get challenge
    const r1 = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`);
    expect(r1.status).toBe(429);
    const challenge = r1.headers['x-hashcash-challenge'];
    const lastColon = challenge.lastIndexOf(':');
    const nonce = challenge.slice(0, lastColon);
    const difficulty = parseInt(challenge.slice(lastColon + 1), 10);

    // Step 2: solve at 4 bits (~16 iterations, <1ms)
    const solution = solvePoW(nonce, difficulty);

    // Step 3: resubmit with X-Hashcash-Nonce + X-Hashcash-Solution → 200
    const r2 = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Hashcash-Nonce', nonce)
      .set('X-Hashcash-Solution', solution);

    expect(r2.status).toBe(200);
    expect(fakeProxy.forward).toHaveBeenCalled();
  });

  it('replay same solution → 429 proof_of_work_invalid (UsedNonceStore single-use)', async () => {
    fakeTrustScore.evaluateScore.mockResolvedValue(0.85);

    // Issue + solve once
    const r1 = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`);
    const challenge = r1.headers['x-hashcash-challenge'];
    const lastColon = challenge.lastIndexOf(':');
    const nonce = challenge.slice(0, lastColon);
    const difficulty = parseInt(challenge.slice(lastColon + 1), 10);
    const solution = solvePoW(nonce, difficulty);

    // First submission consumes the nonce
    const r2 = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Hashcash-Nonce', nonce)
      .set('X-Hashcash-Solution', solution);
    expect(r2.status).toBe(200);

    // Replay same nonce + solution → rejected
    const r3 = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Hashcash-Nonce', nonce)
      .set('X-Hashcash-Solution', solution);
    expect(r3.status).toBe(429);
    expect(r3.body.error).toBe('proof_of_work_invalid');
  });
});
