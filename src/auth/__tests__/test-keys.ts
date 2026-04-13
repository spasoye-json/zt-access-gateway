/**
 * Shared test key fixtures for auth module specs.
 * Uses real jose APIs (D-01: no mocks of jose itself).
 * Generates actual RS256/ES256 key pairs for signature testing.
 */
import {
  SignJWT,
  UnsecuredJWT,
  generateKeyPair,
  exportSPKI,
} from 'jose';
import type { KeyLike } from 'jose';

/** HS256 test secret -- at least 32 chars for HMAC-SHA256 */
export const TEST_HS256_SECRET =
  'test-secret-that-is-at-least-32-chars-long!';

/**
 * Create an HS256-signed JWT with the given payload.
 * Uses real jose SignJWT -- no mocking.
 */
export async function createHs256Token(
  payload: Record<string, unknown>,
  opts?: { expiresIn?: string; jti?: string; secret?: string },
): Promise<string> {
  const key = new TextEncoder().encode(
    opts?.secret ?? TEST_HS256_SECRET,
  );
  let builder = new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(opts?.expiresIn ?? '1h');
  if (opts?.jti) builder = builder.setJti(opts.jti);
  return builder.sign(key);
}

// Module-level caches for key pair generation (expensive crypto ops)
let rs256Cache: {
  publicKey: KeyLike;
  privateKey: KeyLike;
  spki: string;
} | null = null;

let es256Cache: {
  publicKey: KeyLike;
  privateKey: KeyLike;
  spki: string;
} | null = null;

/**
 * Generate (or return cached) RS256 key pair + SPKI export.
 */
export async function createRs256Fixtures(): Promise<{
  publicKey: KeyLike;
  privateKey: KeyLike;
  spki: string;
}> {
  if (rs256Cache) return rs256Cache;
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const spki = await exportSPKI(publicKey);
  rs256Cache = { publicKey, privateKey, spki };
  return rs256Cache;
}

/**
 * Generate (or return cached) ES256 key pair + SPKI export.
 */
export async function createEs256Fixtures(): Promise<{
  publicKey: KeyLike;
  privateKey: KeyLike;
  spki: string;
}> {
  if (es256Cache) return es256Cache;
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const spki = await exportSPKI(publicKey);
  es256Cache = { publicKey, privateKey, spki };
  return es256Cache;
}

/**
 * Create a signed JWT using an asymmetric key (RS256 or ES256).
 */
export async function createAsymmetricToken(
  alg: 'RS256' | 'ES256',
  privateKey: KeyLike,
  payload: Record<string, unknown>,
  opts?: { expiresIn?: string; jti?: string },
): Promise<string> {
  let builder = new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime(opts?.expiresIn ?? '1h');
  if (opts?.jti) builder = builder.setJti(opts.jti);
  return builder.sign(privateKey);
}

/**
 * Create an unsecured JWT with "none" algorithm -- for attack testing (AUTH-03).
 */
export function createNoneAlgToken(
  payload: Record<string, unknown>,
): string {
  return new UnsecuredJWT(payload).setExpirationTime('1h').encode();
}

/**
 * Create an already-expired HS256 token -- for expiry rejection testing (AUTH-02).
 */
export async function createExpiredHs256Token(
  secret?: string,
): Promise<string> {
  const key = new TextEncoder().encode(secret ?? TEST_HS256_SECRET);
  return new SignJWT({ sub: 'expired-user', roles: ['user'] })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('-1h')
    .sign(key);
}
