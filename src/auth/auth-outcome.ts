import type { UserClaims } from './interfaces/user-claims.interface';

/**
 * Auth Outcome — see CONTEXT.md.
 *
 * Discriminated union returned by AuthService.authenticate(). Owns the full
 * answer to "is this token usable right now?" as values, not exceptions.
 * Consumed by exactly two adapters (AuthStage, JwtAuthGuard) once migration
 * lands in #17 and #18. Until then, this type and authenticate() have no
 * production callers — only auth.service.spec.ts.
 */
export type AuthInvalidReason = 'missing' | 'scheme' | 'token';

export type AuthOutcome =
  | { kind: 'ok'; claims: UserClaims }
  | { kind: 'invalid'; reason: AuthInvalidReason; message?: string }
  | { kind: 'revoked' };
