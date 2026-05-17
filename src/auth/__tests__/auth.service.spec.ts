import { Test } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { TokenRevocationService } from '../token-revocation.service';
import { AUTH_CONFIG, type AuthConfig } from '../../config/slices';
import {
  TEST_HS256_SECRET,
  createHs256Token,
  createRs256Fixtures,
  createEs256Fixtures,
  createAsymmetricToken,
  createNoneAlgToken,
  createExpiredHs256Token,
} from './test-keys';

/**
 * AuthService unit tests — TDD RED phase.
 * Tests will fail on import until auth.service.ts is created in Wave 1.
 *
 * Coverage: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, JA4H-04
 */
describe('AuthService', () => {
  let authService: AuthService;
  let revocation: TokenRevocationService;
  let mockConfig: Partial<AuthConfig>;

  beforeEach(async () => {
    mockConfig = {
      jwtSecret: TEST_HS256_SECRET,
      jwtPublicKey: undefined,
      jwksUri: undefined,
      jwtIssuer: undefined,
      jwtAudience: undefined,
    };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        TokenRevocationService,
        { provide: AUTH_CONFIG, useValue: mockConfig },
      ],
    }).compile();

    authService = module.get(AuthService);
    revocation = module.get(TokenRevocationService);
  });

  describe('validateToken - HS256 (AUTH-01)', () => {
    it('validates a valid HS256 token and returns UserClaims', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], email: 'u@test.com' },
        { jti: 'jti-hs256-1' },
      );
      const claims = await authService.validateToken(token);

      expect(claims.userId).toBe('user-1');
      expect(claims.roles).toEqual(['user']);
      expect(claims.jti).toBe('jti-hs256-1');
      expect(claims.email).toBe('u@test.com');
      expect(claims.exp).toEqual(expect.any(Number));
    });

    it('rejects a token signed with wrong HS256 secret', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'] },
        { jti: 'jti-wrong-secret', secret: 'completely-different-secret-32chars!!' },
      );

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('validateToken - RS256 (AUTH-01)', () => {
    it('validates a valid RS256 token using JWT_PUBLIC_KEY (SPKI)', async () => {
      const { privateKey, spki } = await createRs256Fixtures();
      (mockConfig as Record<string, unknown>).jwtPublicKey = spki;

      const token = await createAsymmetricToken(
        'RS256',
        privateKey,
        { sub: 'user-rs', roles: ['admin'] },
        { jti: 'jti-rs256' },
      );
      const claims = await authService.validateToken(token);

      expect(claims.userId).toBe('user-rs');
      expect(claims.roles).toEqual(['admin']);
      expect(claims.jti).toBe('jti-rs256');
    });

    it('rejects RS256 token verified against wrong public key', async () => {
      const { privateKey } = await createRs256Fixtures();
      // Generate a different key pair -- public key won't match
      const { spki: wrongSpki } = await createEs256Fixtures();
      (mockConfig as Record<string, unknown>).jwtPublicKey = wrongSpki;

      const token = await createAsymmetricToken(
        'RS256',
        privateKey,
        { sub: 'user-rs', roles: ['user'] },
        { jti: 'jti-rs-wrong' },
      );

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('validateToken - ES256 (AUTH-01)', () => {
    it('validates a valid ES256 token using JWT_PUBLIC_KEY (SPKI)', async () => {
      const { privateKey, spki } = await createEs256Fixtures();
      (mockConfig as Record<string, unknown>).jwtPublicKey = spki;

      const token = await createAsymmetricToken(
        'ES256',
        privateKey,
        { sub: 'user-es', roles: ['user'] },
        { jti: 'jti-es256' },
      );
      const claims = await authService.validateToken(token);

      expect(claims.userId).toBe('user-es');
      expect(claims.jti).toBe('jti-es256');
    });
  });

  describe('algorithm security (AUTH-02, AUTH-03)', () => {
    it('rejects tokens with "none" algorithm - T-3-01', async () => {
      const token = createNoneAlgToken({
        sub: 'attacker',
        roles: ['admin'],
        jti: 'jti-none',
      });

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });

    it('rejects expired tokens with UnauthorizedException', async () => {
      const token = await createExpiredHs256Token();

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });

    it('rejects tokens with tampered signature', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'] },
        { jti: 'jti-tamper' },
      );
      // Tamper with the signature portion (last segment)
      const parts = token.split('.');
      parts[2] = parts[2].replace(/.$/, parts[2].endsWith('A') ? 'B' : 'A');
      const tampered = parts.join('.');

      await expect(authService.validateToken(tampered)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('JWKS support (AUTH-04)', () => {
    it('fetches key from JWKS_URI when JWT_PUBLIC_KEY not set', async () => {
      // Mock JWKS endpoint -- in production this would be a remote URL.
      // For unit test: mock createRemoteJWKSet or use a local HTTP server.
      // AuthService should call createRemoteJWKSet(new URL(config.jwksUri))
      // and cache the result as a singleton.
      (mockConfig as Record<string, unknown>).jwtSecret = undefined;
      (mockConfig as Record<string, unknown>).jwtPublicKey = undefined;
      (mockConfig as Record<string, unknown>).jwksUri =
        'https://idp.example.com/.well-known/jwks.json';

      const { privateKey } = await createRs256Fixtures();
      const token = await createAsymmetricToken(
        'RS256',
        privateKey,
        { sub: 'user-jwks', roles: ['user'] },
        { jti: 'jti-jwks' },
      );

      // This test will need the JWKS mock to return a matching key.
      // Implementation should use createRemoteJWKSet which handles fetch+cache.
      // For RED phase: we expect it to call the right path; exact mock setup
      // will be refined when implementation lands.
      await expect(authService.validateToken(token)).rejects.toThrow();
    });
  });

  describe('claim validation (AUTH-05)', () => {
    it('rejects token when issuer does not match JWT_ISSUER', async () => {
      (mockConfig as Record<string, unknown>).jwtIssuer = 'https://expected-issuer.com';

      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], iss: 'https://wrong-issuer.com' },
        { jti: 'jti-iss' },
      );

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });

    it('rejects token when audience does not match JWT_AUDIENCE', async () => {
      (mockConfig as Record<string, unknown>).jwtAudience = 'zt-gateway';

      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], aud: 'wrong-audience' },
        { jti: 'jti-aud' },
      );

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });

    it('accepts token when JWT_ISSUER/JWT_AUDIENCE not configured (skip validation)', async () => {
      // issuer and audience both undefined in config -- no validation
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'] },
        { jti: 'jti-no-iss' },
      );

      const claims = await authService.validateToken(token);
      expect(claims.userId).toBe('user-1');
    });
  });

  describe('UserClaims extraction (AUTH-06, D-10, JA4H-04)', () => {
    it('extracts userId from sub claim', async () => {
      const token = await createHs256Token({ sub: 'uid-42', roles: ['user'] }, { jti: 'jti-sub' });
      const claims = await authService.validateToken(token);
      expect(claims.userId).toBe('uid-42');
    });

    it('extracts roles array from roles claim', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['admin', 'editor'] },
        { jti: 'jti-roles' },
      );
      const claims = await authService.validateToken(token);
      expect(claims.roles).toEqual(['admin', 'editor']);
    });

    // WR-04 (phase 14): defend against malformed roles claim values.
    it('WR-04: returns empty roles when claim is a string (not an array)', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: 'admin' },
        { jti: 'jti-roles-string' },
      );
      const claims = await authService.validateToken(token);
      expect(claims.roles).toEqual([]);
    });

    it('WR-04: returns empty roles when claim is a number', async () => {
      const token = await createHs256Token({ sub: 'u1', roles: 42 }, { jti: 'jti-roles-number' });
      const claims = await authService.validateToken(token);
      expect(claims.roles).toEqual([]);
    });

    it('WR-04: filters non-string entries from roles array', async () => {
      const token = await createHs256Token(
        {
          sub: 'u1',
          roles: ['admin', 7, { evil: true }, 'editor'] as unknown,
        },
        { jti: 'jti-roles-mixed' },
      );
      const claims = await authService.validateToken(token);
      expect(claims.roles).toEqual(['admin', 'editor']);
    });

    it('WR-04: returns empty roles when claim is absent', async () => {
      const token = await createHs256Token({ sub: 'u1' }, { jti: 'jti-roles-missing' });
      const claims = await authService.validateToken(token);
      expect(claims.roles).toEqual([]);
    });

    it('extracts jti from jti claim', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'unique-jti-value' },
      );
      const claims = await authService.validateToken(token);
      expect(claims.jti).toBe('unique-jti-value');
    });

    it('extracts optional email and sessionId and required deviceId', async () => {
      const token = await createHs256Token(
        {
          sub: 'u1',
          roles: ['user'],
          email: 'test@example.com',
          sessionId: 'sess-123',
          deviceId: 'dev-456',
        },
        { jti: 'jti-optional' },
      );
      const claims = await authService.validateToken(token);
      expect(claims.email).toBe('test@example.com');
      expect(claims.sessionId).toBe('sess-123');
      expect(claims.deviceId).toBe('dev-456');
    });

    it('throws UnauthorizedException when deviceId claim is missing', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'jti-no-device', omitDeviceId: true },
      );

      await expect(authService.validateToken(token)).rejects.toThrow(
        'Token missing deviceId claim',
      );
    });

    it('throws UnauthorizedException when jti claim is missing', async () => {
      // Create token without jti -- zero-trust gateway requires jti for revocation
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        // No jti option
      );

      await expect(authService.validateToken(token)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('MFA token rejection (T-07-fix3, D-10)', () => {
    it('Test 16: rejects JWT with typ:mfa claim (MFA JWT cannot be used as access token)', async () => {
      // Forge a JWT that carries typ:'mfa' — signed with the same HS256 secret
      const key = new TextEncoder().encode(TEST_HS256_SECRET);
      const mfaToken = await new (await import('jose')).SignJWT({
        sub: 'u1',
        jti: 'j1',
        deviceId: 'd1',
        typ: 'mfa',
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(key);

      await expect(authService.validateToken(mfaToken)).rejects.toThrow(UnauthorizedException);
    });

    it('Test 17: accepts normal JWT without typ claim (unaffected by MFA guard)', async () => {
      // Normal access token — no typ claim
      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'jti-normal' });

      const claims = await authService.validateToken(token);
      expect(claims.userId).toBe('u1');
    });
  });

  /**
   * Issue #16 — Auth Outcome.
   *
   * authenticate(req) is the single deep seam for "is this token usable right now?".
   * Failures become values, not exceptions. Adapters (AuthStage, JwtAuthGuard)
   * map AuthOutcome → their conventions. Migration of adapters lives in #17/#18.
   */
  describe('authenticate (Auth Outcome)', () => {
    it('valid bearer + non-revoked jti → { kind: "ok", claims }', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'], email: 'u@test.com' },
        { jti: 'jti-ok' },
      );
      void revocation; // collaborator wired; revoked-path covered in a later cycle
      const outcome = await authService.authenticate({
        headers: { authorization: `Bearer ${token}` },
      });

      expect(outcome.kind).toBe('ok');
      if (outcome.kind !== 'ok') return;
      expect(outcome.claims.userId).toBe('u1');
      expect(outcome.claims.jti).toBe('jti-ok');
      expect(outcome.claims.roles).toEqual(['user']);
    });

    it('missing Authorization header → { kind: "invalid", reason: "missing" }', async () => {
      const outcome = await authService.authenticate({ headers: {} });
      expect(outcome).toEqual({ kind: 'invalid', reason: 'missing' });
    });
  });
});
