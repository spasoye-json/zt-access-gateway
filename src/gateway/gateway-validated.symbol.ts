/**
 * Phase 13 D-04 — Non-spoofable sentinel.
 *
 * GatewayMiddleware sets (req as any)[GATEWAY_VALIDATED] = true at the same
 * call site that assigns req.user = claims — AFTER pipeline step 5 (auth
 * validateToken) and step 6 (revocation isRevoked) have both succeeded.
 *
 * JwtAuthGuard reads this sentinel between its @Public() check and its
 * validateToken call; if true, the guard returns true immediately without
 * re-running validateToken or isRevoked (Phase 13 SC-2).
 *
 * Why a Symbol, not a string property or header?
 * - A client-controlled HTTP header could spoof a string flag. Symbol identity
 *   is process-private — the only way to obtain THIS symbol is via this import
 *   path. Untrusted input crossing the trust boundary cannot reach it.
 * - Bare req.user is intentionally NOT trusted (defence-in-depth): a future
 *   bug elsewhere in the codebase that assigns req.user without running auth
 *   would not bypass the guard.
 */
export const GATEWAY_VALIDATED: unique symbol = Symbol('gateway:validated');
