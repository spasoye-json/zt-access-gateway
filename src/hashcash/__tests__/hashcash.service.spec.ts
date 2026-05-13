import { HashcashService } from '../hashcash.service';
import { UsedNonceStore } from '../used-nonce-store';
import { HashcashMetrics } from '../hashcash-metrics';
import type { HashcashConfig } from '../../config/slices';
import { hashSolution, countLeadingZeroBits } from '../hashcash.util';

function fakeConfig(
  overrides: Partial<{
    secret: string;
    ttlMs: number;
    min: number;
    max: number;
  }> = {},
): HashcashConfig {
  return {
    hmacSecret: overrides.secret ?? 'a'.repeat(64),
    challengeTtlMs: overrides.ttlMs ?? 120000,
    difficultyMin: overrides.min ?? 4, // collapsed range — fast solves in tests
    difficultyMax: overrides.max ?? 4,
  } as unknown as HashcashConfig;
}

function solveAt(nonce: string, difficulty: number): string {
  // Helper — brute force; with difficulty=4, ~16 iterations average (<1ms)
  for (let i = 0; ; i++) {
    const sol = i.toString(36);
    if (countLeadingZeroBits(hashSolution(nonce, sol)) >= difficulty) return sol;
  }
}

describe('HashcashService', () => {
  let service: HashcashService;
  let store: UsedNonceStore;
  let metrics: HashcashMetrics;

  beforeEach(() => {
    store = new UsedNonceStore(100);
    metrics = new HashcashMetrics();
    // Default test config: min=max=4 → difficulty always 4 regardless of score
    service = new HashcashService(fakeConfig(), store, metrics);
  });

  describe('issueChallenge', () => {
    it('returns { nonce, difficulty, expiresAt } where nonce shape is `<base64url>.<base64url>`', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      expect(typeof issued.nonce).toBe('string');
      expect(issued.nonce.split('.').length).toBe(2);
      expect(issued.nonce.lastIndexOf('.')).toBeGreaterThan(0);
      expect(typeof issued.difficulty).toBe('number');
      expect(typeof issued.expiresAt).toBe('number');
    });

    it('returned difficulty MATCHES payload.diff (single source of truth — anti-bug)', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      const [pB64] = issued.nonce.split('.');
      const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
      expect(issued.difficulty).toBe(payload.diff);
    });

    it('returned expiresAt MATCHES payload.exp (single source of truth)', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      const [pB64] = issued.nonce.split('.');
      const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
      expect(issued.expiresAt).toBe(payload.exp);
    });

    it('payload encodes {v:1, exp, diff, sub, dev, iat} where exp = iat + ttlMs/1000', () => {
      const before = Math.floor(Date.now() / 1000);
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      const after = Math.floor(Date.now() / 1000);
      const [pB64] = issued.nonce.split('.');
      const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
      expect(payload.v).toBe(1);
      expect(payload.diff).toBe(4); // min=max=4 → 4
      expect(payload.sub).toBe('user-1');
      expect(payload.dev).toBe('dev-1');
      expect(payload.iat).toBeGreaterThanOrEqual(before);
      expect(payload.iat).toBeLessThanOrEqual(after);
      expect(payload.exp).toBe(payload.iat + 120);
    });

    it('production curve: with cfg (min=18, max=22), score=0.85 → diff=21 (D-10 lock)', () => {
      const prodService = new HashcashService(fakeConfig({ min: 18, max: 22 }), store, metrics);
      const issued = prodService.issueChallenge('u', 'd', 0.85);
      const [pB64] = issued.nonce.split('.');
      const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
      expect(payload.diff).toBe(21);
      expect(issued.difficulty).toBe(21); // returned value matches encoded value
    });

    it('production curve: with cfg (min=18, max=22), score=0.90 → diff=22', () => {
      const prodService = new HashcashService(fakeConfig({ min: 18, max: 22 }), store, metrics);
      const issued = prodService.issueChallenge('u', 'd', 0.9);
      const [pB64] = issued.nonce.split('.');
      const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
      expect(payload.diff).toBe(22);
      expect(issued.difficulty).toBe(22);
    });

    it('HMAC is HMAC-SHA256(HASHCASH_HMAC_SECRET, payload_bytes)', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      const dot = issued.nonce.lastIndexOf('.');
      const payloadBytes = Buffer.from(issued.nonce.slice(0, dot), 'base64url');
      const providedMac = Buffer.from(issued.nonce.slice(dot + 1), 'base64url');
      const { createHmac } = require('node:crypto');
      const expected = createHmac('sha256', 'a'.repeat(64)).update(payloadBytes).digest();
      expect(providedMac.equals(expected)).toBe(true);
    });

    it('binds nonce to userId (sub) and deviceId (dev) per D-02', () => {
      const a = service.issueChallenge('user-A', 'dev-1', 0.85);
      const b = service.issueChallenge('user-B', 'dev-1', 0.85);
      expect(a.nonce).not.toEqual(b.nonce);
    });
  });

  describe('verifySolution', () => {
    it('happy path: valid nonce + correct solution returns {ok:true}', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      const solution = solveAt(issued.nonce, issued.difficulty);
      const result = service.verifySolution(issued.nonce, solution, 0.85, 'user-1', 'dev-1');
      expect(result.ok).toBe(true);
      if (result.ok) expect(typeof result.iat).toBe('number');
    });

    it('invalid hmac: tampered payload rejected by timingSafeEqual', () => {
      const issued = service.issueChallenge('user-1', 'dev-1', 0.85);
      // Replace the mac segment with 32 zero bytes — same decoded length as a real mac
      // (so the length pre-check passes and we reach timingSafeEqual), but cryptographically
      // unable to match a genuine HMAC-SHA256 over the payload.
      // Avoid tampering the trailing base64url char: a 32-byte mac → 43 chars where the last
      // char encodes only 4 meaningful bits, so half of single-char flips decode to the same
      // mac bytes and the test becomes flaky.
      const dotIdx = issued.nonce.lastIndexOf('.');
      const zeroMac = Buffer.alloc(32, 0).toString('base64url');
      const tampered = `${issued.nonce.slice(0, dotIdx + 1)}${zeroMac}`;
      const result = service.verifySolution(tampered, 'whatever', 0.85, 'user-1', 'dev-1');
      expect(result).toEqual({ ok: false, reason: 'invalid_hmac' });
    });

    it('invalid hmac: malformed nonce (no dot) rejected without throwing', () => {
      const result = service.verifySolution('no-dot-here', 'sol', 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect(['malformed', 'invalid_hmac']).toContain((result as { reason: string }).reason);
    });

    it('invalid hmac: providedMac.length !== 32 rejected before timingSafeEqual', () => {
      // Construct a nonce whose mac segment decodes to fewer than 32 bytes.
      const payloadB64 = Buffer.from(
        JSON.stringify({ v: 1, exp: 9_999_999_999, diff: 4, sub: 'u', dev: 'd', iat: 0 }),
      ).toString('base64url');
      const shortMacB64 = Buffer.from('short').toString('base64url');
      const result = service.verifySolution(`${payloadB64}.${shortMacB64}`, 'sol', 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('invalid_hmac');
      // CRITICAL: did NOT throw ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH
    });

    it('expired: payload with exp <= now is rejected', () => {
      const expiredService = new HashcashService(fakeConfig({ ttlMs: 0 }), store, metrics);
      const issued = expiredService.issueChallenge('u', 'd', 0.85);
      const result = expiredService.verifySolution(issued.nonce, 'irrelevant', 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('expired');
    });

    it('replay: second verifySolution for same nonce returns {ok:false, reason:"replay"}', () => {
      const issued = service.issueChallenge('u', 'd', 0.85);
      const solution = solveAt(issued.nonce, issued.difficulty);
      const first = service.verifySolution(issued.nonce, solution, 0.85, 'u', 'd');
      expect(first.ok).toBe(true);
      const second = service.verifySolution(issued.nonce, solution, 0.85, 'u', 'd');
      expect(second.ok).toBe(false);
      expect((second as { reason: string }).reason).toBe('replay');
    });

    it('difficulty mismatch: payload.diff differs from difficultyForScore(liveScore, min, max) → reject (D-11)', () => {
      // Use prod-curve service so score changes can shift expected difficulty
      const prodService = new HashcashService(fakeConfig({ min: 18, max: 22 }), store, metrics);
      // Issue at score 0.71 (diff=18) but verify with live score 0.85 (expected diff=21)
      const issued = prodService.issueChallenge('u', 'd', 0.71);
      const result = prodService.verifySolution(issued.nonce, 'sol', 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('difficulty_mismatch');
    });

    it('length bound: solution.length > 256 rejected before any hashing', () => {
      const issued = service.issueChallenge('u', 'd', 0.85);
      const big = 'x'.repeat(257);
      const result = service.verifySolution(issued.nonce, big, 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('length_bound');
    });

    it('length bound: solution.length === 0 rejected', () => {
      const issued = service.issueChallenge('u', 'd', 0.85);
      const result = service.verifySolution(issued.nonce, '', 0.85, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('length_bound');
    });

    it('insufficient leading zero bits → reject', () => {
      // Use prod curve so the bar (18 bits) is high enough that 'a' won't pass
      const prodService = new HashcashService(fakeConfig({ min: 18, max: 22 }), store, metrics);
      const issued = prodService.issueChallenge('u', 'd', 0.71);
      const result = prodService.verifySolution(issued.nonce, 'a', 0.71, 'u', 'd');
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe('insufficient_zeros');
    });

    describe('identity binding (D-02)', () => {
      it("rejects with reason 'identity_mismatch' when expectedUserId differs from payload.sub", () => {
        const { nonce, difficulty } = service.issueChallenge('user-A', 'dev-1', 0.85);
        const sol = solveAt(nonce, difficulty);
        const result = service.verifySolution(nonce, sol, 0.85, 'user-B', 'dev-1');
        expect(result).toEqual({ ok: false, reason: 'identity_mismatch' });
      });

      it("rejects with reason 'identity_mismatch' when expectedDeviceId differs from payload.dev", () => {
        const { nonce, difficulty } = service.issueChallenge('user-A', 'dev-1', 0.85);
        const sol = solveAt(nonce, difficulty);
        const result = service.verifySolution(nonce, sol, 0.85, 'user-A', 'dev-2');
        expect(result).toEqual({ ok: false, reason: 'identity_mismatch' });
      });

      it('accepts when expectedUserId and expectedDeviceId both match payload.sub / payload.dev', () => {
        const { nonce, difficulty } = service.issueChallenge('user-A', 'dev-1', 0.85);
        const sol = solveAt(nonce, difficulty);
        const result = service.verifySolution(nonce, sol, 0.85, 'user-A', 'dev-1');
        expect(result).toEqual({ ok: true, iat: expect.any(Number) });
      });

      it('mismatched verify does NOT consume the single-use slot — legitimate verify still succeeds afterward', () => {
        const { nonce, difficulty } = service.issueChallenge('user-A', 'dev-1', 0.85);
        const sol = solveAt(nonce, difficulty);
        // Attacker tries to replay user-A's puzzle as user-B
        const blocked = service.verifySolution(nonce, sol, 0.85, 'user-B', 'dev-1');
        expect(blocked).toEqual({ ok: false, reason: 'identity_mismatch' });
        // Legitimate user-A submits — must still succeed (identity check is BEFORE replay-store add)
        const ok = service.verifySolution(nonce, sol, 0.85, 'user-A', 'dev-1');
        expect(ok).toMatchObject({ ok: true });
      });
    });

    it('emits metrics: solved on happy path, failed on rejection', async () => {
      const issued = service.issueChallenge('u', 'd', 0.85);
      const solution = solveAt(issued.nonce, issued.difficulty);
      service.verifySolution(issued.nonce, solution, 0.85, 'u', 'd'); // solved
      service.verifySolution('garbage', 'x', 0.85, 'u', 'd'); // failed (malformed)
      const json = await metrics.registry.getMetricsAsJSON();
      const total = json.find((x) => x.name === 'zt_gateway_hashcash_total');
      const solved = total.values.find((v) => v.labels.outcome === 'solved');
      const failed = total.values.find((v) => v.labels.outcome === 'failed');
      expect((solved as { value: number }).value).toBeGreaterThanOrEqual(1);
      expect((failed as { value: number }).value).toBeGreaterThanOrEqual(1);
    });
  });
});
