/**
 * Phase 5 — augment Express Request with fields populated by the gateway pipeline.
 *
 * D-07: HashcashGuard reads request.trustScore. Phase 10 GatewayMiddleware will set this
 * upstream so the guard avoids a duplicate evaluateScore call. In Phase 5 standalone E2E
 * the field is undefined and the guard falls back to TrustScoreService.evaluateScore.
 *
 * Phase 7 — adds mfaToken for MfaGuard (D-10).
 */
declare global {
  namespace Express {
    interface Request {
      /** Optional trust score [0,1] populated by Phase 10 GatewayMiddleware (D-07). */
      trustScore?: number;
      /** MFA token claims populated by MfaGuard (Phase 10). Absent until guard validates token. */
      mfaToken?: import('../mfa/interfaces/mfa-token-claims.interface').MfaTokenClaims;
    }
  }
}

export {};
