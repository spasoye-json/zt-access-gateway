// Set required env vars BEFORE any imports — @nestjs/config validates at module load time.
process.env.MTLS_CA_CERT_PATH = '/tmp/test-ca.pem';
process.env.MTLS_CLIENT_CERT_PATH = '/tmp/test-client.pem';
process.env.MTLS_CLIENT_KEY_PATH = '/tmp/test-key.pem';
process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
process.env.RATE_LIMIT_MAX = '5';
process.env.RATE_LIMIT_WINDOW_MS = '60000';

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { AppModule } from '../src/app.module';
import { HttpExceptionFilter } from '../src/shared/http-exception.filter';

describe('Bootstrap middleware stack (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    // Mirror main.ts middleware order exactly (RESEARCH.md Pattern 6)
    app.use(helmet());
    app.enableCors({ origin: '*' });
    app.use(
      rateLimit({
        windowMs: 60000,
        max: 5,
        standardHeaders: true,
        legacyHeaders: false,
      }),
    );
    app.useGlobalFilters(new HttpExceptionFilter());
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health returns 200 with status ok', async () => {
    const response = await request(app.getHttpServer())
      .get('/health')
      .expect(200);

    expect(response.body).toMatchObject({
      status: 'ok',
      timestamp: expect.any(String),
    });
  });

  it('Helmet security headers are present on every response', async () => {
    const response = await request(app.getHttpServer())
      .get('/health')
      .expect(200);

    // Helmet sets x-content-type-options to prevent MIME sniffing (T-01-10)
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    // Helmet sets x-frame-options to prevent clickjacking
    expect(response.headers['x-frame-options']).toBeDefined();
    // Helmet sets x-dns-prefetch-control
    expect(response.headers['x-dns-prefetch-control']).toBeDefined();
  });

  it('CORS headers are present for matching origin', async () => {
    const response = await request(app.getHttpServer())
      .get('/health')
      .set('Origin', 'http://localhost')
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBeDefined();
  });

  it('Unknown unauth route returns structured 401 JSON without stack trace', async () => {
    // Post-Phase-10: GatewayMiddleware enforces auth before route resolution;
    // 404 would leak route existence to unauth callers. See 10-05-SUMMARY.md.
    const response = await request(app.getHttpServer())
      .get('/nonexistent-route-that-does-not-exist')
      .expect(401);

    // Positive structural confirmation — actual middleware response shape
    // is `{ error: 'auth_required', requestId }` (gateway.middleware.ts:140,147).
    // Per CONTEXT.md D-06 + RESEARCH.md Q1: assertion adapts to observed shape.
    expect(response.body).toHaveProperty('error', 'auth_required');
    expect(response.body).toHaveProperty('requestId');
    // Stack trace must never appear in HTTP responses (T-01-13).
    // This is the test's load-bearing security invariant — preserved verbatim.
    expect(response.body).not.toHaveProperty('stack');
  });

  it('Rate limiting returns 429 after exceeding RATE_LIMIT_MAX requests', async () => {
    // Spin up a dedicated app instance with max:3 so this test is fully self-contained
    // and does not depend on quota consumed by prior tests (WR-04).
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const isolatedApp = moduleFixture.createNestApplication();
    isolatedApp.use(helmet());
    isolatedApp.use(
      rateLimit({
        windowMs: 60000,
        max: 3,
        standardHeaders: true,
        legacyHeaders: false,
      }),
    );
    isolatedApp.useGlobalFilters(new HttpExceptionFilter());
    await isolatedApp.init();

    const server = isolatedApp.getHttpServer();
    // Consume all 3 allowed requests
    for (let i = 0; i < 3; i++) {
      await request(server).get('/health');
    }
    // 4th request must be rate-limited
    const response = await request(server).get('/health');
    expect(response.status).toBe(429);

    await isolatedApp.close();
  });
});
