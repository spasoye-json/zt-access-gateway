import { aesGcmEncrypt, aesGcmDecrypt } from '../aes-gcm.util';

// 32-byte key base64-encoded (44 chars)
const TEST_KEY = Buffer.alloc(32, 0x42).toString('base64'); // 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI='

describe('aes-gcm.util', () => {
  it('aesGcmEncrypt + aesGcmDecrypt round-trip returns original plaintext', () => {
    const plaintext = 'JBSWY3DPEHPK3PXP'; // base32 TOTP secret
    const ciphertext = aesGcmEncrypt(plaintext, TEST_KEY);
    expect(aesGcmDecrypt(ciphertext, TEST_KEY)).toBe(plaintext);
  });

  it('aesGcmDecrypt returns null for tampered ciphertext (auth tag mismatch)', () => {
    const ciphertext = aesGcmEncrypt('secret', TEST_KEY);
    const buf = Buffer.from(ciphertext, 'base64');
    buf[buf.length - 1] ^= 0xff; // flip last byte of auth tag
    expect(aesGcmDecrypt(buf.toString('base64'), TEST_KEY)).toBeNull();
  });

  it('aesGcmDecrypt returns null for wrong key', () => {
    const ciphertext = aesGcmEncrypt('secret', TEST_KEY);
    const wrongKey = Buffer.alloc(32, 0x00).toString('base64');
    expect(aesGcmDecrypt(ciphertext, wrongKey)).toBeNull();
  });

  it('aesGcmEncrypt produces different ciphertext on each call (random IV)', () => {
    const c1 = aesGcmEncrypt('same-plaintext', TEST_KEY);
    const c2 = aesGcmEncrypt('same-plaintext', TEST_KEY);
    expect(c1).not.toBe(c2);
  });
});
