/**
 * Phase 9 Wave 0 RED stubs for AuditService (AUDT-01, AUDT-03, AUDT-04, AUDT-06).
 * Implementation lands in Plan 09-01.
 */
describe('AuditService', () => {
  describe('writeBlocking() — WAL retry path (AUDT-03, AUDT-04)', () => {
    it.todo('inserts audit entry on first attempt (no retries)');
    it.todo('retries up to maxRetries times with 50ms→100ms→200ms exponential backoff');
    it.todo('throws AuditExhaustedException after 3 failed attempts');
    it.todo('total attempts equals maxRetries (default 3)');
    it.todo('does NOT swallow AuditExhaustedException — caller must catch');
  });

  describe('record() — best-effort path (AUDT-01, AUDT-06)', () => {
    it.todo('inserts audit entry when DB succeeds');
    it.todo('catches DB errors and logs console.warn (never throws)');
    it.todo("emits 'audit.record_failed' on DB error (D-05 seam to MetricsService)");
    it.todo('logs CHALLENGE decision via record()');
    it.todo('logs DENY decision via record()');
    it.todo('persists eventType for HONEYPOT_TRIGGERED entries (AUDT-06)');
  });
});
