import { execSync } from 'child_process';
import * as path from 'path';

/**
 * Phase 14 Plan 04 D-13 — Permanent regression guard.
 *
 * MfaGuard was deleted in Phase 14 (SC-4). It had zero @UseGuards consumers
 * and was never registered via APP_GUARD anywhere; GatewayMiddleware step 9b
 * calls MfaService.validateMfaToken directly. This spec fails the build if
 * anyone re-introduces a reference to the deleted guard class.
 *
 * Implementation per CONTEXT D-13: shell out to grep (mirrors the Phase 13 D-03
 * regression spec for the deleted hashcash guard). No allowlist — MfaGuard has
 * no past-tense breadcrumbs worth preserving.
 */
describe('MfaGuard regression guard (Phase 14 D-13)', () => {
  const repoRoot = path.resolve(__dirname, '../../..');
  const selfRelative = path.relative(repoRoot, __filename);

  function grepMfaGuard(dir: string): string {
    const out = execSync(`grep -rE '\\bMfaGuard\\b' ${dir} --include='*.ts' || true`, {
      cwd: repoRoot,
      encoding: 'utf8',
    });
    return out
      .split('\n')
      .filter((line) => line && !line.startsWith(selfRelative + ':'))
      .join('\n');
  }

  it('no source file under src/ references MfaGuard', () => {
    const hits = grepMfaGuard('src');
    expect(hits).toBe('');
  });

  it('no test file under tests/ references MfaGuard', () => {
    const hits = grepMfaGuard('tests');
    expect(hits).toBe('');
  });
});
