/**
 * AES-256-GCM encrypt/decrypt helpers for TOTP secrets at rest (Phase 7 D-15).
 *
 * Output format: base64(iv[12] || ciphertext || authTag[16])
 * Key: 32-byte buffer, base64-decoded from MFA_TOTP_ENCRYPTION_KEY env.
 *
 * SECURITY: aesGcmDecrypt returns null on ANY failure — never throws.
 * Callers treat null as unknown_user → 401. Never log the decrypted value.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGO = 'aes-256-gcm' as const;
const IV_BYTES = 12; // 96-bit IV — recommended for GCM
const AUTH_TAG_BYTES = 16;

export function aesGcmEncrypt(plaintext: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, authTag]).toString('base64');
}

/**
 * Returns null on authentication failure (tampered ciphertext or wrong key).
 * Never throws — callers map null to an mfa_invalid error response.
 */
export function aesGcmDecrypt(ciphertextBase64: string, keyBase64: string): string | null {
  try {
    const key = Buffer.from(keyBase64, 'base64');
    const buf = Buffer.from(ciphertextBase64, 'base64');
    if (buf.length < IV_BYTES + AUTH_TAG_BYTES) return null;
    const iv = buf.subarray(0, IV_BYTES);
    const authTag = buf.subarray(buf.length - AUTH_TAG_BYTES);
    const ciphertext = buf.subarray(IV_BYTES, buf.length - AUTH_TAG_BYTES);
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
