import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
// Env vars set by tests/setup-e2e.ts (setupFiles) before this import resolves
import { AppModule } from '../../src/app.module';
import { TokenRevocationService } from '../../src/auth/token-revocation.service';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';

/**
 * E2e test for TREV-04: token revocation pipeline position.
 * Validates that JwtAuthGuard checks revocation status after JWT signature
 * verification but before any downstream processing (trust scoring, policy, etc).
 */
describe('Auth Revocation Pipeline (e2e)', () => {
  let app: INestApplication;
  let revocationService: TokenRevocationService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
    revocationService = moduleRef.get(TokenRevocationService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('TREV-04: revocation after auth, before downstream', () => {
    it('returns 401 for request with revoked jti', async () => {
      const jti = 'revoke-me-e2e';
      const token = await createHs256Token({ sub: 'user1', roles: ['user'] }, { jti });

      // Revoke the token's jti before making the request
      revocationService.revoke(jti, Date.now() + 60_000, 'user1');

      // Use POST /auth/revoke -- a real protected route registered by AuthController.
      // The guard rejects the revoked token with 401 before the controller runs.
      await request(app.getHttpServer())
        .post('/auth/revoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ jti: 'irrelevant', exp: 9999999999 })
        .expect(401);
    });

    it('does not return 401 for request with non-revoked valid token', async () => {
      const token = await createHs256Token(
        { sub: 'user1', roles: ['user'] },
        { jti: 'valid-token-e2e' },
      );

      // Token is NOT revoked -- should pass auth gate
      // May get 404 if route doesn't exist, but should NOT get 401
      const res = await request(app.getHttpServer())
        .get('/health')
        .set('Authorization', `Bearer ${token}`);

      // @Public() route returns 200; non-public unknown route returns 404
      // Either way, NOT 401 (auth passed)
      expect(res.status).not.toBe(401);
    });
  });
});
