/** Phase 9 — output shape for GET /audit/logs (camelCase, dates parsed). */
export interface AuditLog {
  id: number;
  userId: string;
  resource: string;
  action: string;
  decision: 'allow' | 'challenge' | 'deny';
  trustScore: number | null;
  ja4hFingerprint: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  eventType: string | null;
  createdAt: Date;
}

/** Internal DB row shape returned by pg before camelCase mapping. */
export interface AuditLogRow {
  id: string;
  user_id: string;
  resource: string;
  action: string;
  decision: 'allow' | 'challenge' | 'deny';
  trust_score: string | null;
  ja4h_fingerprint: string | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  event_type: string | null;
  created_at: Date;
}
