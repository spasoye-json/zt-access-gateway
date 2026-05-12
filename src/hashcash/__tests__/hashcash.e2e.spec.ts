/**
 * Phase 5 Plan 06 — full HCSH-01..HCSH-07 e2e cycle through real NestJS pipeline.
 *
 * Proves:
 *  - score <= 0.7 → request passes (no challenge)
 *  - score > 0.7 + no PoW headers → 429 + X-Hashcash-Challenge: nonce:4
 *  - solve at 4 bits + resubmit → 200 (controller reached)
 *  - replay same solution → 429 (single-use enforced)
 *
 * Difficulty pinned to 4 via HASHCASH_DIFFICULTY_MIN=MAX=4 — proves D-17 env knob
 * flows through AppConfigService → HashcashService.cfg.diffMin/Max → both
 * issueChallenge AND verifySolution (via difficultyForScore(score, 4, 4) === 4).
 * Closes the HCSH-06 gap: returns 200, not 429, on Step 3.
 */

// Set env BEFORE importing AppModule — ConfigModule validates at decoration time.
process.env.NODE_ENV = 'test';
process.env.HASHCASH_HMAC_SECRET = process.env.HASHCASH_HMAC_SECRET ?? 'a'.repeat(64);
process.env.HASHCASH_DIFFICULTY_MIN = '4';
process.env.HASHCASH_DIFFICULTY_MAX = '4'; // collapsed range — issue + verify both yield 4
process.env.HASHCASH_TRIGGER_THRESHOLD = process.env.HASHCASH_TRIGGER_THRESHOLD ?? '0.7';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret-that-is-at-least-32-chars-long!';
if (!process.env.MTLS_CA_CERT_PATH) process.env.MTLS_CA_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_CERT_PATH) process.env.MTLS_CLIENT_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_KEY_PATH) process.env.MTLS_CLIENT_KEY_PATH = '/dev/null';
if (!process.env.MTLS_ALLOWED_SUBJECTS) process.env.MTLS_ALLOWED_SUBJECTS = 'cn=test';
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = 'postgresql://localhost:5432/zt_test';
// Phase 7 MFA vars — required by config validation after MfaModule added to AppModule
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-test-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
// Phase 8 Proxy vars — required by config validation after ProxyModule added to AppModule
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });

import { Test } from '@nestjs/testing';
import { Controller, Get, INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { TrustScoreService } from '../../trust-score/trust-score.service';
import { createHs256Token } from '../../auth/__tests__/test-keys';
import { hashSolution, countLeadingZeroBits } from '../hashcash.util';

// Lightweight controller mounted only for this test — exercises the full guard pipeline.
@Controller()
class TestProtectedController {
  @Get('/_test/protected')
  ping(): { ok: true } {
    return { ok: true };
  }
}

function solvePoW(nonce: string, difficulty: number): string {
  for (let i = 0; ; i++) {
    const sol = i.toString(36);
    if (countLeadingZeroBits(hashSolution(nonce, sol)) >= difficulty) return sol;
  }
}

// Phase 10 D-02: HashcashGuard APP_GUARD removed (plan 10-05 T2). Hashcash
// enforcement migrated into GatewayMiddleware. This test was specifically
// designed against the guard-on-route model and therefore no longer exercises
// the live codepath (the gateway pipeline now denies unregistered proxy routes
// like `/_test/protected` before reaching the hashcash step). Plan 10-06 owns
// the new full-pipeline e2e sweep that validates hashcash via GatewayMiddleware
// against a registered service. Skipping here documents the migration.
describe.skip('Hashcash e2e (superseded by plan 10-06 GatewayMiddleware e2e)', () => {
  let app: INestApplication;
  const evaluateScore = jest.fn();
  let token: string;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
      controllers: [TestProtectedController],
    })
      .overrideProvider(TrustScoreService)
      .useValue({
        evaluateScore,
        recordTrustContextAfterAllow: jest.fn(),
      })
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();

    // Mint a real HS256 JWT — same shape AuthService extracts (sub/jti/deviceId required).
    token = await createHs256Token({ sub: 'user-1', roles: ['user'] }, { jti: 'jti-e2e-1' });
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    evaluateScore.mockReset();
  });

  it('low score: passes through without challenge', async () => {
    evaluateScore.mockResolvedValue(0.5);
    const res = await request(app.getHttpServer())
      .get('/_test/protected')
      .set('Authorization', `Bearer ${token}`)
      .set('x-ja4h', 'fp-1');
    expect(res.status).toBe(200);
    expect(res.headers['x-hashcash-challenge']).toBeUndefined();
    expect(res.body).toEqual({ ok: true });
  });

  it('full cycle: high-risk request returns 429; solving and resubmitting returns 200; replaying returns 429', async () => {
    evaluateScore.mockResolvedValue(0.85);

    // Step 1: no PoW headers → 429 with challenge
    const r1 = await request(app.getHttpServer())
      .get('/_test/protected')
      .set('Authorization', `Bearer ${token}`)
      .set('x-ja4h', 'fp-1');
    expect(r1.status).toBe(429);
    expect(r1.headers['x-hashcash-challenge']).toBeDefined();
    expect(r1.headers['retry-after']).toBe('1');
    expect(r1.body.error).toBe('proof_of_work_required');

    const challenge = r1.headers['x-hashcash-challenge'];
    const lastColon = challenge.lastIndexOf(':');
    const nonce = challenge.slice(0, lastColon);
    const difficulty = parseInt(challenge.slice(lastColon + 1), 10);
    // PROOF env override flows end-to-end via plan 01 parameterization
    // and plan 03 cfg wiring — service issued at min=max=4 → diff=4.
    expect(difficulty).toBe(4);
    expect(nonce.length).toBeGreaterThan(0);
    expect(nonce).toBe(r1.body.nonce);

    // Step 2: solve at 4 bits (~16 iterations, <1ms)
    const solution = solvePoW(nonce, difficulty);

    // Step 3: resubmit with X-Hashcash-Nonce + X-Hashcash-Solution → 200
    // verifySolution re-derives expected diff via difficultyForScore(0.85, 4, 4) === 4,
    // matches payload.diff === 4 (D-11), and the 4-bit solution clears the leading-zero bar.
    const r2 = await request(app.getHttpServer())
      .get('/_test/protected')
      .set('Authorization', `Bearer ${token}`)
      .set('x-ja4h', 'fp-1')
      .set('X-Hashcash-Nonce', nonce)
      .set('X-Hashcash-Solution', solution);
    expect(r2.status).toBe(200);
    expect(r2.body).toEqual({ ok: true });

    // Step 4: replay same solution → 429 (single-use enforced)
    const r3 = await request(app.getHttpServer())
      .get('/_test/protected')
      .set('Authorization', `Bearer ${token}`)
      .set('x-ja4h', 'fp-1')
      .set('X-Hashcash-Nonce', nonce)
      .set('X-Hashcash-Solution', solution);
    expect(r3.status).toBe(429);
    expect(r3.body.error).toBe('proof_of_work_invalid');
  }, 30000);
});
