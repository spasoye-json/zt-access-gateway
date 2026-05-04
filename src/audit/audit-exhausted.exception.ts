/**
 * Thrown by AuditService.writeBlocking() after maxRetries failed inserts.
 * Phase 10 GatewayMiddleware catches and returns 503 (audit-before-allow).
 */
export class AuditExhaustedException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditExhaustedException';
  }
}
