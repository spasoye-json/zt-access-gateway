/**
 * TOTP code generator — CLI used by scripts/scenarios/scenario-8.sh and -9.sh.
 *
 * Uses the SAME implementation the server validates against
 * (src/shared/totp.util.ts) so generated codes always match. Reads a base32
 * secret from argv[2] and prints the current 6-digit code. Demo / UAT only.
 *
 * Usage: node -r ts-node/register scripts/totp.ts <base32Secret>
 */
import { totp } from '../src/shared/totp.util';

const secret = process.argv[2];
if (!secret) {
  process.stderr.write('usage: totp.ts <base32Secret>\n');
  process.exit(1);
}

process.stdout.write(totp.generate(secret) + '\n');
