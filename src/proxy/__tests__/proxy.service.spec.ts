/**
 * Wave 0 RED stubs for ProxyService.
 * Covers: PRXY-01 (mTLS forwarding), PRXY-02 (header strip + inject),
 *         PRXY-04 (circuit breaker state), PRXY-05 (exponential backoff retry).
 */
describe('ProxyService', () => {
  describe('onModuleInit (D-03)', () => {
    it.todo('creates one CircuitBreaker per service in registry');
    it.todo('breakers are stored in a Map<serviceName, CircuitBreaker>');
  });
  describe('forward() — header sanitization (PRXY-02)', () => {
    it.todo('strips Authorization header from outgoing request');
    it.todo('strips Cookie header from outgoing request');
    it.todo('strips x-forwarded-for header (re-set by gateway)');
    it.todo('strips any incoming x-gateway-* headers');
    it.todo('injects x-user-id from UserClaims.userId');
    it.todo('injects x-roles as comma-separated UserClaims.roles');
    it.todo('injects x-trust-score as String(score)');
    it.todo('injects x-gateway-request: true');
  });
  describe('forward() — mTLS (PRXY-01)', () => {
    it.todo('passes MtlsService.getHttpsAgent() as axios httpsAgent option');
  });
  describe('forward() — retry loop (PRXY-05, D-10)', () => {
    it.todo('retries on ECONNREFUSED with 100ms → 200ms → 400ms backoff');
    it.todo('retries on ETIMEDOUT');
    it.todo('retries on ECONNRESET');
    it.todo('retries on 502/503/504 status codes');
    it.todo('does NOT retry on 4xx status codes');
    it.todo('does NOT retry on 500/501 (per Pitfall 3 — only gateway errors retried)');
    it.todo('after maxRetries exhausted, throws to opossum (which records single failure per D-11)');
  });
  describe('forward() — circuit breaker (PRXY-04, D-02, D-11)', () => {
    it.todo('OPEN state → throws ServiceUnavailableException without calling axios');
    it.todo('per-service breakers are isolated — service-A failure does not trip service-B');
    it.todo('breaker only records failure once per request, not per retry attempt (D-11)');
  });
  describe('forward() — registry + DNS (PRXY-03, PRXY-06, PRXY-07)', () => {
    it.todo('rejects unknown service before any DNS resolve or axios call');
    it.todo('calls DnsRebindingGuard.assertSafe before opossum.fire');
  });
});
