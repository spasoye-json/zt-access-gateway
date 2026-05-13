/**
 * Phase A2 — ValidationPipe body-spoof regression.
 *
 * Proves the defence-in-depth claim made by the AuthenticatedClaims brand:
 * even if a request body contains `__authenticatedByGateway: true`, the global
 * ValidationPipe (whitelist + forbidNonWhitelisted, mirrored from src/main.ts)
 * either rejects (forbidNonWhitelisted) or strips (whitelist) the field before
 * it can reach a controller — so it cannot land on req.user via a copy-from-
 * body bug.
 *
 * Scope: validation-pipe only. No AuthGuard / GatewayMiddleware wiring needed.
 *
 * Run: node_modules/.bin/jest --config tests/jest-e2e.json tests/integration/body-spoof.e2e-spec.ts
 */

import { Body, Controller, INestApplication, Module, Post, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { IsString } from 'class-validator';
import * as request from 'supertest';

class SpoofProbeDto {
  @IsString()
  name!: string;
}

@Controller('test')
class SpoofProbeController {
  @Post()
  echo(@Body() body: SpoofProbeDto): { body: SpoofProbeDto; keys: string[] } {
    return { body, keys: Object.keys(body) };
  }
}

@Module({ controllers: [SpoofProbeController] })
class SpoofProbeModule {}

describe('Phase A2 — ValidationPipe body-spoof regression', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [SpoofProbeModule] }).compile();
    app = moduleRef.createNestApplication();
    // Mirrors src/main.ts step 5 — must keep behaviour aligned.
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects bodies containing __authenticatedByGateway with 400 (forbidNonWhitelisted)', async () => {
    const res = await request(app.getHttpServer())
      .post('/test')
      .send({ name: 'ok', __authenticatedByGateway: true });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/__authenticatedByGateway/);
  });

  it('baseline: clean body without the brand field passes validation', async () => {
    const res = await request(app.getHttpServer()).post('/test').send({ name: 'ok' });
    expect(res.status).toBe(201);
    expect(res.body.keys).toEqual(['name']);
    expect(res.body.body).toEqual({ name: 'ok' });
    // Sanity: the brand field is NOT present after validation.
    expect('__authenticatedByGateway' in res.body.body).toBe(false);
  });
});
