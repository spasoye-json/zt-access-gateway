/**
 * Phase 5 Wave 0 stubs — HCSH-02, HCSH-04, HCSH-05 (HashcashService issue/verify with HMAC).
 * Filled in by 05-03-PLAN.md.
 */
describe('HashcashService', () => {
  describe('issueChallenge', () => {
    it.todo('returns a nonce of shape `<base64url>.<base64url>` (one dot separator at last index)');
    it.todo('payload encodes {v:1, exp, diff, sub, dev, iat} where exp = iat + ttlMs/1000');
    it.todo('HMAC is HMAC-SHA256(HASHCASH_HMAC_SECRET, payload_bytes)');
    it.todo('binds nonce to userId (sub) and deviceId (dev) per D-02');
  });

  describe('verifySolution', () => {
    it.todo('happy path: valid HMAC + unexpired + matching difficulty + leading zeros >= diff → returns true');
    it.todo('invalid hmac: tampered payload rejected by timingSafeEqual (constant-time)');
    it.todo('invalid hmac: malformed nonce (no dot) rejected without throwing');
    it.todo('invalid hmac: providedMac.length !== 32 rejected before timingSafeEqual (no ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH thrown)');
    it.todo('expired: nonce with exp <= now rejected');
    it.todo('replay: second verifySolution for same nonce returns false (UsedNonceStore single-use)');
    it.todo('difficulty mismatch: payload.diff differs from difficultyForScore(liveScore) → reject (D-11)');
    it.todo('length bound: solution.length > 256 rejected before any hash computation (T-5-HBOMB)');
    it.todo('length bound: solution.length === 0 rejected');
    it.todo('insufficient leading zero bits → reject');
  });
});
