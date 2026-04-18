/**
 * Request-scoped inputs for trust scoring (D-05).
 * Fields originate from JWT + HTTP — treat as untrusted.
 */
export interface TrustContext {
  userId: string;
  deviceId: string;
  ip: string;
  ja4h: string;
  /** Wall time for the request; defaults to `new Date()` in providers when omitted. */
  requestTimestamp?: Date;
}
