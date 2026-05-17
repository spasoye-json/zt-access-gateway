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
