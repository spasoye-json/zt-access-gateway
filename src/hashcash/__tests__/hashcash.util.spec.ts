/**
 * Phase 5 Wave 0 stubs — HCSH-03 (difficultyForScore) + HCSH-05 (countLeadingZeroBits, hashSolution).
 * Filled in by 05-01-PLAN.md.
 */
describe('hashcash.util', () => {
  describe('difficultyForScore', () => {
    it.todo('linear curve: 0.71 → 18, 0.75 → 19, 0.80 → 20, 0.85 → 21, 0.90 → 22');
    it.todo('clamps to 22 for scores > 0.9 (including 1.0 terminal)');
    it.todo('returns 18 at the 0.71 boundary (D-08 strict > 0.7)');
  });

  describe('countLeadingZeroBits', () => {
    it.todo('all-zero buffer (32 bytes) → 256 bits');
    it.todo('Buffer [0x01, ...zeros] → 7 bits');
    it.todo('Buffer [0x00, 0x80, ...zeros] → 8 bits');
    it.todo('Buffer [0x00, 0x7f, ...zeros] → 9 bits');
    it.todo('Buffer [0x08, ...zeros] → 4 bits');
  });

  describe('hashSolution', () => {
    it.todo('SHA-256 of UTF-8 concat of nonce + solution returns 32-byte Buffer');
    it.todo('different solutions produce different digests for same nonce');
  });
});
