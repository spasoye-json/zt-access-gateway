/**
 * Phase 5 Wave 0 stubs — HCSH-01, HCSH-02, HCSH-04, HCSH-06, HCSH-07.
 * Filled in by 05-05-PLAN.md.
 */
describe('HashcashGuard', () => {
  describe('bypass', () => {
    it.todo('@Public() route returns true without consulting service or score');
    it.todo('OPTIONS request returns true (CORS preflight bypass — D-discretion)');
  });

  describe('trustScore seam (D-07)', () => {
    it.todo('uses request.trustScore when set (no fallback evaluateScore call)');
    it.todo('falls back to TrustScoreService.evaluateScore(ctx) when request.trustScore is undefined');
  });

  describe('score <= 0.7', () => {
    it.todo('score === 0.7 returns true (D-08 strictly >, equality passes through)');
    it.todo('score === 0.5 returns true (no PoW required)');
  });

  describe('score > 0.7 (issues 429)', () => {
    it.todo('no X-Hashcash-Solution header → 429 with X-Hashcash-Challenge: <nonce>:<difficulty>');
    it.todo('429 body shape: { error: "proof_of_work_required", nonce, difficulty, expiresAt }');
    it.todo('Retry-After: 1 header set');
    it.todo('returns false (request short-circuited)');
  });

  describe('reads solution header', () => {
    it.todo('X-Hashcash-Solution header value forwarded to HashcashService.verifySolution');
    it.todo('header value > 256 chars rejected with 429 invalid (T-5-HBOMB) before service call');
  });

  describe('valid solution', () => {
    it.todo('HashcashService.verifySolution → true ⇒ guard returns true (request proceeds)');
    it.todo('HashcashService.verifySolution → false ⇒ guard issues a fresh 429 with new nonce');
  });

  describe('metrics', () => {
    it.todo('counter inc({outcome:"issued", difficulty}) on challenge issuance');
    it.todo('counter inc({outcome:"solved", difficulty}) on successful verify');
    it.todo('counter inc({outcome:"failed", difficulty}) on rejected verify');
  });

  describe('histogram', () => {
    it.todo('solveSeconds observes (now - payload.iat) seconds on successful verify only');
  });
});
