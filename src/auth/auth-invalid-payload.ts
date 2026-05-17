import type { Request } from 'express';
import { AUTH_INVALID_TOKEN, type ThreatSignalPayload } from '../policy/policy-events';
import { extractIp, extractJa4h } from '../shared/request-context.util';

/**
 * Issue #16 — single source of truth for the AUTH_INVALID_TOKEN payload.
 *
 * Both adapters (AuthStage, JwtAuthGuard) will emit through this helper after
 * #17/#18 so payloads stay byte-identical across seams. Closes the
 * 13-REVIEW.md WARNING about emission drift.
 *
 * Note: the issue body sketched `(req, outcome)` but `AuthOutcome.invalid`
 * carries no field the existing payload contract surfaces, so `outcome` is
 * omitted. A follow-up that wants to emit the failure reason can add the
 * parameter without touching either adapter.
 */
export function buildAuthInvalidPayload(req: Request): ThreatSignalPayload {
  return {
    type: AUTH_INVALID_TOKEN,
    ip: extractIp(req),
    ja4h: extractJa4h(req),
    ts: Date.now(),
  };
}
