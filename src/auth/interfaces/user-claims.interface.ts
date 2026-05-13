/**
 * Standardized JWT token payload extracted after validation.
 * Threaded through all downstream pipeline layers (trust, policy, audit, proxy).
 * D-10: userId, roles, jti, exp, deviceId required; email, sessionId optional.
 */
export interface UserClaims {
  /** From JWT 'sub' claim */
  userId: string;
  /** From JWT 'roles' claim */
  roles: string[];
  /** From JWT 'jti' claim -- required for revocation (TREV-04) */
  jti: string;
  /** Token expiration (Unix seconds) */
  exp: number;
  /** Optional -- audit logging */
  email?: string;
  /** Optional -- JA4H drift detection, MFA session binding */
  sessionId?: string;
  /** Required -- trust scoring, MFA device binding (Phase 4 D-11) */
  deviceId: string;
}

/**
 * Phase A2 — branded variant proving the request was authenticated by
 * GatewayMiddleware (i.e. validateToken + isRevoked both succeeded). Only
 * GatewayMiddleware constructs this; JwtAuthGuard reads it to short-circuit
 * re-validation on AUTH_ONLY routes.
 *
 * Spoof-safety: the brand field is unknown to any DTO, so the global
 * ValidationPipe (whitelist + forbidNonWhitelisted, see src/main.ts) strips it
 * from request bodies before it could ever land on req.user. Defence-in-depth:
 * req.user is only ever assigned by middleware/guard code, never deserialized
 * from the wire.
 */
export type AuthenticatedClaims = UserClaims & {
  readonly __authenticatedByGateway: true;
};
