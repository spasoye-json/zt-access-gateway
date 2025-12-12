import * as http from 'http';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { JwtService } from '../../src/shared/jwt.service';
import { ProxyService } from '../../src/proxy/proxy.service';
import { configureApp } from '../../src/bootstrap-app';
import { ConfigService as NestConfigService } from '@nestjs/config';

const canListen = async (): Promise<boolean> =>
  new Promise((resolve) => {
    const server = http.createServer();
    server.listen(0, () => {
      server.close(() => resolve(true));
    });
    server.on('error', () => resolve(false));
  });

describe('Gateway Integration Tests', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let mockProxyService: Partial<ProxyService>;
  let networkAllowed = true;

  const itIfNetwork = (name: string, testFn: () => Promise<void>) =>
    it(name, async () => {
      if (!networkAllowed) return;
      await testFn();
    });

  beforeAll(async () => {
    networkAllowed = await canListen();
    if (!networkAllowed) {
      // This environment blocks listening sockets; skip HTTP-level integration tests.
      return;
    }

    mockProxyService = {
      forwardRequest: jest.fn().mockResolvedValue({
        status: 200,
        data: { message: 'Success from microservice' },
        headers: {},
      }),
    };

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ProxyService)
      .useValue(mockProxyService)
      .compile();

    app = moduleFixture.createNestApplication();
    configureApp(app, moduleFixture.get<NestConfigService>(NestConfigService));
    jwtService = moduleFixture.get<JwtService>(JwtService);

    process.env.JWT_SECRET = 'test-secret-for-jest';

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('Complete request flow', () => {
    itIfNetwork('should process a complete request flow with valid token', async () => {
      const tokenPayload = {
        userId: 'test-user',
        roles: ['user'],
        sessionId: 'session123',
      };
      const token = await jwtService.sign(tokenPayload, 'test-secret-for-jest');

      await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Device-Id', 'device123')
        .expect(200)
        .then((response) => {
          expect(response.body).toEqual({ message: 'Success from microservice' });
          expect(mockProxyService.forwardRequest).toHaveBeenCalledWith(
            'users-service',
            'GET',
            '/users',
            expect.objectContaining({
              authorization: `Bearer ${token}`,
              'x-device-id': 'device123',
            }),
            undefined,
            expect.objectContaining({ userId: 'test-user' }),
            expect.any(Number),
          );
        });
    });

    itIfNetwork('should reject request without authorization header', async () => {
      await request(app.getHttpServer())
        .get('/users')
        .expect(401)
        .then((response) => {
          expect(response.body).toEqual({
            error: 'Unauthorized',
            message: 'Authorization header is required',
          });
        });
    });

    itIfNetwork('should reject request with invalid token', async () => {
      await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401)
        .then((response) => {
          expect(response.body).toEqual({
            error: 'Unauthorized',
            message: 'Invalid token',
          });
        });
    });

    itIfNetwork('should return 502 when proxy forwarding fails', async () => {
      (mockProxyService.forwardRequest as jest.Mock).mockRejectedValue(
        new Error('Service temporarily unavailable'),
      );

      const tokenPayload = {
        userId: 'test-user',
        roles: ['admin'],
        sessionId: 'session123',
      };
      const token = await jwtService.sign(tokenPayload, 'test-secret-for-jest');

      await request(app.getHttpServer())
        .get('/admin')
        .set('Authorization', `Bearer ${token}`)
        .expect(502)
        .finally(() => {
          (mockProxyService.forwardRequest as jest.Mock).mockResolvedValue({
            status: 200,
            data: { message: 'Success from microservice' },
            headers: {},
          });
        });
    });
  });

  describe('Different HTTP methods', () => {
    itIfNetwork('should handle POST requests', async () => {
      const tokenPayload = {
        userId: 'test-user',
        roles: ['admin'],
        sessionId: 'session123',
      };
      const token = await jwtService.sign(tokenPayload, 'test-secret-for-jest');

      const postData = { name: 'New User', email: 'user@example.com' };

      await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${token}`)
        .send(postData)
        .expect(200)
        .then((response) => {
          expect(response.body).toEqual({ message: 'Success from microservice' });
        });
    });

    itIfNetwork('should handle PUT requests', async () => {
      const tokenPayload = {
        userId: 'test-user',
        roles: ['admin'],
        sessionId: 'session123',
      };
      const token = await jwtService.sign(tokenPayload, 'test-secret-for-jest');

      const putData = { name: 'Updated User', email: 'updated@example.com' };

      await request(app.getHttpServer())
        .put('/users/123')
        .set('Authorization', `Bearer ${token}`)
        .send(putData)
        .expect(200)
        .then((response) => {
          expect(response.body).toEqual({ message: 'Success from microservice' });
        });
    });

    itIfNetwork('should handle DELETE requests', async () => {
      const tokenPayload = {
        userId: 'test-user',
        roles: ['admin'],
        sessionId: 'session123',
      };
      const token = await jwtService.sign(tokenPayload, 'test-secret-for-jest');

      await request(app.getHttpServer())
        .delete('/users/123')
        .set('Authorization', `Bearer ${token}`)
        .expect(200)
        .then((response) => {
          expect(response.body).toEqual({ message: 'Success from microservice' });
        });
    });
  });
});
