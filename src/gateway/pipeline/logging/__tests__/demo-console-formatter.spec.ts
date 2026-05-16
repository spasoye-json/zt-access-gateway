import chalk from 'chalk';
import { formatStageLine } from '../demo-console-formatter';

beforeAll(() => {
  // Force chalk to a deterministic colour level so snapshots are stable
  // across CI/TTY/Jest environments.
  chalk.level = 1;
});

describe('formatStageLine', () => {
  it('renders a PASS line containing reqId, stageId, glyph, status word, ms and detail kvs', () => {
    const line = formatStageLine('abcdef01', 'auth', 'pass', 3, {
      user: 'alice',
      alg: 'HS256',
    });

    expect(line).toContain('abcdef01');
    expect(line).toContain('auth');
    expect(line).toContain('✓');
    expect(line).toContain('PASS');
    expect(line).toContain('3ms');
    expect(line).toContain('user=alice');
    expect(line).toContain('alg=HS256');
  });

  it('colour-codes each of the four statuses with its own ANSI sequence', () => {
    const pass = formatStageLine('r1', 'auth', 'pass', 1);
    const deny = formatStageLine('r2', 'auth', 'deny', 1);
    const chall = formatStageLine('r3', 'auth', 'chall', 1);
    const skip = formatStageLine('r4', 'auth', 'skip', 1);

    expect(pass).toContain(chalk.green('✓ PASS '));
    expect(deny).toContain(chalk.red('✗ DENY '));
    expect(chall).toContain(chalk.yellow('⚠ CHALL'));
    expect(skip).toContain(chalk.dim('⊘ SKIP '));
  });

  it('snapshots each status at fixed widths', () => {
    expect(formatStageLine('abcdef01', 'auth', 'pass', 3, { user: 'alice' })).toMatchSnapshot(
      'pass',
    );
    expect(formatStageLine('abcdef01', 'auth', 'deny', 0, { reason: 'no-token' })).toMatchSnapshot(
      'deny',
    );
    expect(formatStageLine('abcdef01', 'hashcash', 'chall', 12, { bits: '20' })).toMatchSnapshot(
      'chall',
    );
    expect(formatStageLine('abcdef01', 'mfa', 'skip', 0)).toMatchSnapshot('skip');
  });
});
