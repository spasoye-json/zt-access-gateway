/**
 * Phase 6 — Policy subject construction + resource/action normalization (D-04, D-06, D-07).
 *
 * No NestJS DI, no side effects. Single source of truth for `user:<id>` / `role:<r>`
 * shape (closes PITFALLS.md Pitfall #6 — subject format drift). Reusable from tests,
 * the service, and (future) client tooling.
 */
import type { UserClaims } from '../auth/interfaces/user-claims.interface';

/**
 * D-04: build the subject set Casbin enforces against. Iterated by PolicyEvaluator
 * with multi-role any-allows semantics (D-05).
 */
export function buildSubjects(claims: UserClaims): string[] {
  const subjects: string[] = [`user:${claims.userId}`];
  for (const role of claims.roles ?? []) {
    subjects.push(`role:${role}`);
  }
  return subjects;
}

/**
 * D-07: canonical request path for Casbin obj.
 * - Strip query string (`?...`)
 * - Strip trailing slash (preserve root '/')
 * - PRESERVE CASE — keyMatch2 is case-exact and Pitfall 9 documents that lowercasing breaks `/Users` etc.
 */
export function normalizeResource(rawPath: string): string {
  const q = rawPath.indexOf('?');
  let p = q >= 0 ? rawPath.slice(0, q) : rawPath;
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p;
}

/**
 * D-06: HTTP method uppercased — matches existing `regexMatch(r.act, p.act)` in
 * `policy/model.conf` against rules like `(GET|POST|PUT|PATCH|DELETE)`.
 */
export function normalizeAction(method: string): string {
  return method.toUpperCase();
}
