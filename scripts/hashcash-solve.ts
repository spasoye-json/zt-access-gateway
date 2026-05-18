/**
 * Hashcash PoW solver — CLI used by scripts/scenarios/scenario-4.sh.
 *
 * Reads the nonce + difficulty from CLI args (or stdin JSON) and prints the
 * solution string to stdout. Uses the same SHA-256 + leading-zero-bits
 * convention as src/hashcash/hashcash.util.ts (Pitfall 6 — byte-identical
 * UTF-8 concat of nonce + solution).
 *
 * Usage:
 *   node -r ts-node/register scripts/hashcash-solve.ts <nonce> <difficulty>
 *
 * Stays a thin shell over hashSolution + countLeadingZeroBits so any drift
 * in the production hashing convention surfaces as a build-time import error.
 */
import { hashSolution, countLeadingZeroBits } from '../src/hashcash/hashcash.util';

function solve(nonce: string, difficulty: number): string {
  for (let i = 0; ; i++) {
    const solution = i.toString();
    if (countLeadingZeroBits(hashSolution(nonce, solution)) >= difficulty) {
      return solution;
    }
  }
}

function main(): void {
  const nonce = process.argv[2];
  const difficulty = parseInt(process.argv[3] ?? '', 10);
  if (!nonce || !Number.isFinite(difficulty) || difficulty < 1) {
    process.stderr.write('usage: hashcash-solve.ts <nonce> <difficulty>\n');
    process.exit(1);
  }
  process.stdout.write(solve(nonce, difficulty) + '\n');
}

main();
