/**
 * Pure node:crypto TOTP/HOTP implementation (RFC 6238 / RFC 4226).
 *
 * Replaces @otplib/v12-adapter to avoid the ESM-only @scure/base dependency
 * that crashes the compiled CJS bundle in Node 18 (ERR_REQUIRE_ESM).
 *
 * Supports the same surface used by MfaService:
 *   generateSecret()    — 20-byte random base32 secret (160 bits, same as otplib default)
 *   generate(secret)    — current TOTP code (SHA-1, 6 digits, 30s window)
 *   verify({token, secret}) — accepts ±1 step window (same as otplib default)
 */
import { createHmac, randomBytes } from 'node:crypto';

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Buffer {
  const s = input.toUpperCase().replace(/=+$/, '');
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const ch of s) {
    const idx = BASE32_CHARS.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 character: ${ch}`);
    buf = (buf << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((buf >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function base32Encode(bytes: Buffer): string {
  let buf = 0;
  let bits = 0;
  let out = '';
  for (const byte of bytes) {
    buf = (buf << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_CHARS[(buf >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_CHARS[(buf << (5 - bits)) & 0x1f];
  return out;
}

function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  // writeBigUInt64BE requires bigint; use two 32-bit writes for Node 18 compat
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac('sha1', key).update(msg).digest();
  const offset = hmac[19] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, '0');
}

function currentCounter(): number {
  return Math.floor(Date.now() / 1000 / 30);
}

export const totp = {
  /** Generate a random 20-byte base32 secret (160 bits — same as otplib default). */
  generateSecret(): string {
    return base32Encode(randomBytes(20));
  },

  /** Generate the current TOTP code for a base32 secret. */
  generate(secret: string): string {
    return hotp(base32Decode(secret), currentCounter());
  },

  /**
   * Verify a TOTP code against a base32 secret.
   * Accepts ±1 step window (matches otplib default behaviour).
   */
  verify({ token, secret }: { token: string; secret: string }): boolean {
    const key = base32Decode(secret);
    const t = currentCounter();
    for (const delta of [-1, 0, 1]) {
      if (hotp(key, t + delta) === token) return true;
    }
    return false;
  },
};
