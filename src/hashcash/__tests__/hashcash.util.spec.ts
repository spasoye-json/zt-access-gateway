import { createHash } from 'node:crypto';
import { difficultyForScore, countLeadingZeroBits, hashSolution } from '../hashcash.util';

describe('hashcash.util', () => {
  describe('difficultyForScore', () => {
    // D-10 production curve — min=18, max=22 (locked by CONTEXT.md D-10)
    // bits = clamp(round(18 + (score - 0.7) * 20), 18, 22)
    describe('production curve (min=18, max=22) — D-10', () => {
      it.each<[number, number]>([
        [0.71, 18],
        [0.75, 19],
        [0.8, 20],
        [0.85, 21],
        [0.9, 22],
        [0.95, 22], // clamped
        [1.0, 22], // terminal — still clamped
      ])('score %f → %i bits', (score, expected) => {
        expect(difficultyForScore(score, 18, 22)).toBe(expected);
      });

      // Explicit D-10 lock — preserves the spec'd anchors
      it('D-10 anchor: score=0.7 → 18 bits', () => {
        expect(difficultyForScore(0.7, 18, 22)).toBe(18);
      });
      it('D-10 anchor: score=0.8 → 20 bits', () => {
        expect(difficultyForScore(0.8, 18, 22)).toBe(20);
      });
      it('D-10 anchor: score=0.9 → 22 bits', () => {
        expect(difficultyForScore(0.9, 18, 22)).toBe(22);
      });

      it('returns 18 at the 0.71 boundary', () => {
        expect(difficultyForScore(0.71, 18, 22)).toBe(18);
      });

      it('clamps to 22 for scores > 0.9', () => {
        expect(difficultyForScore(0.91, 18, 22)).toBe(22);
        expect(difficultyForScore(1.0, 18, 22)).toBe(22);
      });
    });

    // Test/CI override curve — collapsed range (min === max), used by e2e tests
    describe('test override curve (min=max=4)', () => {
      it.each<[number, number]>([
        [0.5, 4],
        [0.71, 4],
        [0.85, 4],
        [1.0, 4],
      ])('score %f with min=max=4 → 4 bits', (score, expected) => {
        expect(difficultyForScore(score, 4, 4)).toBe(expected);
      });
    });

    // Asymmetric override — proves the general formula is self-consistent
    describe('asymmetric overrides', () => {
      it('min=8, max=12 anchors at score endpoints', () => {
        expect(difficultyForScore(0.7, 8, 12)).toBe(8);
        expect(difficultyForScore(0.9, 8, 12)).toBe(12);
      });
    });
  });

  describe('countLeadingZeroBits', () => {
    const pad = (head: number[], target = 32): Buffer =>
      Buffer.from([...head, ...Array(target - head.length).fill(0)]);

    it.each<[Buffer, number]>([
      [Buffer.alloc(32, 0), 256],
      [pad([0x01]), 7],
      [pad([0x00, 0x80]), 8],
      [pad([0x00, 0x7f]), 9],
      [pad([0x08]), 4],
    ])('buffer %# → %i bits', (buf, expected) => {
      expect(countLeadingZeroBits(buf)).toBe(expected);
    });
  });

  describe('hashSolution', () => {
    it('returns 32-byte Buffer matching SHA-256(nonce + solution) UTF-8 concat', () => {
      const nonce = 'abc.def';
      const solution = 'xyz';
      const expected = createHash('sha256')
        .update(nonce + solution, 'utf8')
        .digest();
      const actual = hashSolution(nonce, solution);
      expect(actual.equals(expected)).toBe(true);
      expect(actual.length).toBe(32);
    });

    it('different solutions produce different digests for same nonce', () => {
      const a = hashSolution('nonce', 'one');
      const b = hashSolution('nonce', 'two');
      expect(a.equals(b)).toBe(false);
    });
  });
});
