import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { AppConfigService } from '../config.service';

// Helper: set all required env vars (mTLS + JWT)
function setRequiredEnv() {
  process.env.MTLS_CA_CERT_PATH = '/tmp/ca.pem';
  process.env.MTLS_CLIENT_CERT_PATH = '/tmp/client.pem';
  process.env.MTLS_CLIENT_KEY_PATH = '/tmp/client-key.pem';
  process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
  process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
}

const joiSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  CORS_ORIGIN: Joi.string().default('*'),
  RATE_LIMIT_WINDOW_MS: Joi.number().default(60000),
  RATE_LIMIT_MAX: Joi.number().default(100),
  MTLS_CA_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_KEY_PATH: Joi.string().required(),
  MTLS_ALLOWED_SUBJECTS: Joi.string().required(),
  // Phase 3: JWT Auth (D-11)
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_PUBLIC_KEY: Joi.string().optional(),
  JWKS_URI: Joi.string().uri().optional(),
  JWT_ISSUER: Joi.string().optional(),
  JWT_AUDIENCE: Joi.string().optional(),
});

async function createModuleWithEnv() {
  const module = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        ignoreEnvFile: true,
        validationSchema: joiSchema,
        validationOptions: { abortEarly: false },
      }),
    ],
    providers: [AppConfigService],
  }).compile();
  return module.get(AppConfigService);
}

describe('AppConfigService', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    // Restore original env
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  describe('validation — fail-fast (CONF-01)', () => {
    it('throws when MTLS_CA_CERT_PATH is missing', async () => {
      setRequiredEnv();
      delete process.env.MTLS_CA_CERT_PATH;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('throws listing ALL missing vars at once (not one at a time)', async () => {
      // Remove all 4 required mTLS vars
      delete process.env.MTLS_CA_CERT_PATH;
      delete process.env.MTLS_CLIENT_CERT_PATH;
      delete process.env.MTLS_CLIENT_KEY_PATH;
      delete process.env.MTLS_ALLOWED_SUBJECTS;

      let errorMessage = '';
      try {
        await createModuleWithEnv();
      } catch (err: unknown) {
        errorMessage = err instanceof Error ? err.message : String(err);
      }

      expect(errorMessage).toContain('MTLS_CA_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_KEY_PATH');
      expect(errorMessage).toContain('MTLS_ALLOWED_SUBJECTS');
    });
  });

  describe('typed getters (CONF-02)', () => {
    it('port getter returns PORT from env', async () => {
      setRequiredEnv();
      process.env.PORT = '4000';

      const service = await createModuleWithEnv();
      expect(service.port).toBe(4000);
    });

    it('port getter returns 3000 when PORT not set', async () => {
      setRequiredEnv();
      delete process.env.PORT;

      const service = await createModuleWithEnv();
      expect(service.port).toBe(3000);
    });

    it('corsOrigin getter returns CORS_ORIGIN from env', async () => {
      setRequiredEnv();
      process.env.CORS_ORIGIN = 'https://example.com';

      const service = await createModuleWithEnv();
      expect(service.corsOrigin).toBe('https://example.com');
    });

    it("corsOrigin defaults to '*' when not set", async () => {
      setRequiredEnv();
      delete process.env.CORS_ORIGIN;

      const service = await createModuleWithEnv();
      expect(service.corsOrigin).toBe('*');
    });

    it('rateLimitWindowMs getter returns number from env', async () => {
      setRequiredEnv();
      process.env.RATE_LIMIT_WINDOW_MS = '30000';

      const service = await createModuleWithEnv();
      expect(service.rateLimitWindowMs).toBe(30000);
    });

    it('rateLimitMax getter returns number from env', async () => {
      setRequiredEnv();
      process.env.RATE_LIMIT_MAX = '50';

      const service = await createModuleWithEnv();
      expect(service.rateLimitMax).toBe(50);
    });

    it('mtlsCaCertPath getter returns MTLS_CA_CERT_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsCaCertPath).toBe('/tmp/ca.pem');
    });

    it('mtlsClientCertPath getter returns MTLS_CLIENT_CERT_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsClientCertPath).toBe('/tmp/client.pem');
    });

    it('mtlsClientKeyPath getter returns MTLS_CLIENT_KEY_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsClientKeyPath).toBe('/tmp/client-key.pem');
    });

    it('mtlsAllowedSubjects getter returns parsed array', async () => {
      setRequiredEnv();
      process.env.MTLS_ALLOWED_SUBJECTS = 'cn1,cn2,cn3';

      const service = await createModuleWithEnv();
      expect(service.mtlsAllowedSubjects).toEqual(['cn1', 'cn2', 'cn3']);
    });
  });

  describe('Phase 1 only config groups (CONF-03)', () => {
    it('does not expose database getters', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect((service as unknown as Record<string, unknown>).databaseUrl).toBeUndefined();
    });
  });

  describe('JWT config group (CONF-03 Phase 3, D-11)', () => {
    it('throws when JWT_SECRET is missing', async () => {
      setRequiredEnv();
      delete process.env.JWT_SECRET;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('throws when JWT_SECRET is shorter than 32 chars', async () => {
      setRequiredEnv();
      process.env.JWT_SECRET = 'too-short';

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('jwtSecret getter returns JWT_SECRET value', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtSecret).toBe('test-secret-that-is-at-least-32-chars-long!');
    });

    it('jwtPublicKey returns undefined when JWT_PUBLIC_KEY not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtPublicKey).toBeUndefined();
    });

    it('jwtPublicKey returns value when JWT_PUBLIC_KEY is set', async () => {
      setRequiredEnv();
      process.env.JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----';
      const service = await createModuleWithEnv();
      expect(service.jwtPublicKey).toBe('-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----');
    });

    it('jwksUri returns undefined when JWKS_URI not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwksUri).toBeUndefined();
    });

    it('jwksUri returns value when JWKS_URI is set', async () => {
      setRequiredEnv();
      process.env.JWKS_URI = 'https://idp.example.com/.well-known/jwks.json';
      const service = await createModuleWithEnv();
      expect(service.jwksUri).toBe('https://idp.example.com/.well-known/jwks.json');
    });

    it('jwtIssuer returns undefined when JWT_ISSUER not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtIssuer).toBeUndefined();
    });

    it('jwtAudience returns undefined when JWT_AUDIENCE not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtAudience).toBeUndefined();
    });
  });
});
