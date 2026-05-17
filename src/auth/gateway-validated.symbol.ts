/**
 * Non-spoofable brand attached to req by AuthStage after a successful
 * authenticate() — see CONTEXT.md "Auth Outcome".
 *
 * JwtAuthGuard (after #18) checks `req[GATEWAY_VALIDATED] === true` to skip
 * re-validating a request the gateway already authenticated. Symbol identity
 * is the security boundary: request bodies cannot construct a Symbol-keyed
 * property, so the brand cannot be forged via JSON input.
 *
 * Deliberately NOT Symbol.for-registered — that would let attackers retrieve
 * the same Symbol from the global registry by name.
 */
export const GATEWAY_VALIDATED = Symbol('gateway:validated');
