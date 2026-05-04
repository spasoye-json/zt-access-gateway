/**
 * Phase 9 — input shape for audit writes (AUDT-01, AUDT-02, AUDT-06).
 * `userId` is required (gateway never lets unauthenticated requests reach audit).
 * Optional fields persist as NULL when undefined.
 * `eventType` distinguishes special audit events (e.g., 'HONEYPOT_TRIGGERED' — AUDT-06).
 */
export interface AuditEntry {
  userId: string;
  resource: string;
  action: string;
  decision: 'allow' | 'challenge' | 'deny';
  trustScore?: number;
  ja4hFingerprint?: string;
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
  eventType?: string;
}
