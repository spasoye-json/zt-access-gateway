/**
 * Phase 5 — augment Express Request with fields populated by the gateway pipeline.
 *
 * D-07: request.trustScore is populated by GatewayMiddleware pipeline step 5
 * (Phase 10) for downstream consumers that need a single canonical score per
 * request without re-evaluating. Standalone routes (no GatewayMiddleware) leave
 * the field undefined; consumers MUST tolerate that and recompute via
 * TrustScoreService.evaluateScore.
 *
 * Phase 7 — adds mfaToken for MfaGuard (D-10).
 *
 * Phase 8 — adds proxyTarget + boPlaStripped for ProxyService/BoPlaInterceptor.
 */
declare global {
  namespace Express {
    interface Request {
      /** Optional trust score [0,1] populated by Phase 10 GatewayMiddleware (D-07). */
      trustScore?: number;
      /** MFA token claims populated by MfaGuard (Phase 10). Absent until guard validates token. */
      mfaToken?: import('../mfa/interfaces/mfa-token-claims.interface').MfaTokenClaims;
      /** Target service name extracted from URL path prefix by ProxyService (Phase 10). */
      proxyTarget?: string;
      /** True when BoPlaInterceptor stripped at least one field from the response (Phase 10). */
      boPlaStripped?: boolean;
    }
  }
}

export {};
