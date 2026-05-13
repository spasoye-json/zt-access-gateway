/**
 * Mint a demo HS256 JWT for the walking-skeleton scenario.
 *
 * Usage:
 *   node -r ts-node/register scripts/mint-demo-jwt.ts                 # Alice, roles=['user']
 *   SUB=bob ROLES=user,admin node -r ts-node/register scripts/mint-demo-jwt.ts
 *
 * Reads JWT_SECRET from env (.env.demo). Prints the token to stdout.
 * Demo only — never use these claims in production.
 */
import { SignJWT } from 'jose';
import { randomUUID } from 'crypto';

async function main(): Promise<void> {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    process.stderr.write('JWT_SECRET must be set and >= 32 chars\n');
    process.exit(1);
  }

  const sub = process.env.SUB ?? 'alice';
  const roles = (process.env.ROLES ?? 'user').split(',').map((r) => r.trim());
  const deviceId = process.env.DEVICE_ID ?? `${sub}-device-1`;
  const ttl = process.env.TTL ?? '1h';

  const token = await new SignJWT({ roles, deviceId })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(sub)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(new TextEncoder().encode(secret));

  process.stdout.write(token + '\n');
}

void main();
