import type { ConfigService } from '@nestjs/config';

/**
 * Auth slice (Phase 3 D-11).
 *
 * JWT validation knobs. `jwtSecret` is the HS256 secret;
 * `jwtPublicKey`/`jwksUri` enable RS256/ES256. Issuer/audience claims
 * skip validation when undefined.
 */
export interface AuthConfig {
  /** HS256 signing/verification secret. Required. Min 32 chars. */
  readonly jwtSecret: string;
  /** PEM-encoded SPKI public key for RS256/ES256. Optional. */
  readonly jwtPublicKey: string | undefined;
  /** Remote JWKS endpoint URL. Optional. Used when JWT_PUBLIC_KEY not set. */
  readonly jwksUri: string | undefined;
  /** Expected JWT issuer claim. Optional -- skips iss validation when unset. */
  readonly jwtIssuer: string | undefined;
  /** Expected JWT audience claim. Optional -- skips aud validation when unset. */
  readonly jwtAudience: string | undefined;
}

export const AUTH_CONFIG = Symbol('AUTH_CONFIG');

export function buildAuthConfig(env: ConfigService): AuthConfig {
  return Object.freeze({
    jwtSecret: env.get<string>('JWT_SECRET')!,
    jwtPublicKey: env.get<string>('JWT_PUBLIC_KEY'),
    jwksUri: env.get<string>('JWKS_URI'),
    jwtIssuer: env.get<string>('JWT_ISSUER'),
    jwtAudience: env.get<string>('JWT_AUDIENCE'),
  });
}
