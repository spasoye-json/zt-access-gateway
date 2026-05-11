import { execSync } from 'child_process';
import * as path from 'path';

/**
 * Phase 13 D-03 — Permanent regression guard.
 *
 * HashcashGuard was deleted in Phase 13 (SC-1). It has no live consumer:
 * GatewayMiddleware calls HashcashService directly at pipeline step 8 since
 * Phase 10 D-02 removed the APP_GUARD registration. This spec fails the build
 * if anyone re-introduces a reference to the deleted guard class.
 *
 * Implementation per CONTEXT D-03: shell-out to grep. Lint-rule alternative
 * was rejected (would require a custom ESLint rule + maintenance burden).
 */
describe('HashcashGuard regression guard (Phase 13 D-03)', () => {
  const repoRoot = path.resolve(__dirname, '../../..');
  const selfRelative = path.relative(
    repoRoot,
    __filename,
  );

  function grepHashcashGuard(dir: string): string {
    try {
      const out = execSync(
        `grep -rE '\\bHashcashGuard\\b' ${dir} --include='*.ts' || true`,
        { cwd: repoRoot, encoding: 'utf8' },
      );
      // Filter out this spec file's own self-reference.
      return out
        .split('\n')
        .filter((line) => line && !line.startsWith(selfRelative + ':'))
        .join('\n');
    } catch (err) {
      // grep with `|| true` swallows non-zero; any throw here is a real failure.
      throw new Error(`grep failed: ${(err as Error).message}`);
    }
  }

  it('no source file under src/ references HashcashGuard', () => {
    const hits = grepHashcashGuard('src');
    expect(hits).toBe('');
  });

  it('no test file under tests/ references HashcashGuard', () => {
    const hits = grepHashcashGuard('tests');
    expect(hits).toBe('');
  });
});
