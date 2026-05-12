/**
 * MFA JWT payload claims (D-10).
 * typ: 'mfa' prevents cross-use with main JWTs (AuthService rejects typ:'mfa';
 * MfaService.validateMfaToken rejects any typ !== 'mfa').
 */
export interface MfaTokenClaims {
  sub: string; // userId
  jti: string; // unique token ID — stored in mfa_tokens for revocation
  deviceId: string;
  fpHash: string; // SHA-256(userId|deviceId|ip) hex (D-05)
  typ: 'mfa';
  iat: number; // Unix seconds
  exp: number; // Unix seconds
}
