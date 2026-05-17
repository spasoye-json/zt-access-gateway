import chalk from 'chalk';

/**
 * Phase Demo — pure formatter for one stage-narrative line.
 *
 * Output shape (whitespace-padded columns; chalk-coloured by status):
 *
 *   <reqId>  <stageId>      <glyph> <STATUS>   <ms>ms   k=v k=v ...
 *
 * Detail keys are emitted in insertion order. The function is pure — no
 * Logger, no env reads — so it snapshots deterministically once `chalk.level`
 * is fixed by the test setup.
 */
export type StageStatus = 'pass' | 'deny' | 'chall' | 'skip' | 'promo';

const STATUS_TABLE: Record<
  StageStatus,
  { glyph: string; word: string; paint: (s: string) => string }
> = {
  pass: { glyph: '✓', word: 'PASS ', paint: (s) => chalk.green(s) },
  deny: { glyph: '✗', word: 'DENY ', paint: (s) => chalk.red(s) },
  chall: { glyph: '⚠', word: 'CHALL', paint: (s) => chalk.yellow(s) },
  skip: { glyph: '⊘', word: 'SKIP ', paint: (s) => chalk.dim(s) },
  // Slice E (#6): CHALLENGE → ALLOW promotion via a valid x-mfa-token. Same
  // green as PASS because the promotion succeeded, but a distinct word so the
  // audience sees that a CHALLENGE was lifted rather than passing untouched.
  promo: { glyph: '✓', word: 'PROMO', paint: (s) => chalk.green(s) },
};

const REQ_ID_W = 8;
const STAGE_ID_W = 14;
const STATUS_W = 7; // "✓ PASS " visual width (glyph + space + 5)
const MS_W = 6;

function padRight(s: string, w: number): string {
  return s.length >= w ? s : s + ' '.repeat(w - s.length);
}

function padLeft(s: string, w: number): string {
  return s.length >= w ? s : ' '.repeat(w - s.length) + s;
}

function renderDetail(detail: Record<string, string> | undefined): string {
  if (!detail) return '';
  const parts: string[] = [];
  for (const [k, v] of Object.entries(detail)) {
    parts.push(`${k}=${v}`);
  }
  return parts.join(' ');
}

export function formatStageLine(
  reqId: string,
  stageId: string,
  status: StageStatus,
  ms: number,
  detail?: Record<string, string>,
): string {
  const entry = STATUS_TABLE[status];
  const reqCol = chalk.gray(padRight(reqId.slice(0, REQ_ID_W), REQ_ID_W));
  const stageCol = chalk.cyan(padRight(stageId, STAGE_ID_W));
  const statusCol = entry.paint(padRight(`${entry.glyph} ${entry.word}`, STATUS_W));
  const msCol = chalk.gray(padLeft(`${Math.max(0, Math.round(ms))}ms`, MS_W));
  const detailCol = chalk.dim(renderDetail(detail));
  return `${reqCol}  ${stageCol}  ${statusCol}  ${msCol}  ${detailCol}`.trimEnd();
}
