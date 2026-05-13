import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  POLICY_DENY,
  AUTH_INVALID_TOKEN,
  HONEYPOT_TRIGGER,
  MFA_FAILED,
  MFA_RATE_LIMITED,
  MFA_ENROLLMENT_RESET,
  MFA_ENROLLMENT_CONFIRMED,
  MFA_INFRA_ERROR,
  MFA_SECRET_DECRYPT_FAILED,
  AUDIT_SIGNAL,
  ThreatSignalPayload,
} from '../policy/policy-events';
import {
  FINGERPRINT_BLACKLIST_SIZE_CHANGED,
  FINGERPRINT_DRIFT_DETECTED,
  AUTH_TOKEN_REVOKED,
  AUDIT_RECORD_FAILED,
  FingerprintBlacklistSizeChangedPayload,
} from '../metrics/metrics-events';

/**
 * Phase A3 — compile-time-checked emit wrapper around EventEmitter2.
 *
 * Central type-map: event-name constant -> payload shape.
 * `Record<string, never>` declares "no payload data" while still forcing call
 * sites to pass `{}` (preserves today's wire shape at auth.controller.ts:80
 * and ja4h-drift.provider.ts:26).
 *
 * AUDIT_RECORD_FAILED is the lone outlier: it is emitted with NO payload arg
 * today; we keep that wire shape by typing the payload as `void` and providing
 * a variadic overload in TypedEvents.emit that omits the second argument.
 *
 * Listeners stay on raw EventEmitter2 (@OnEvent decorator) — this is purely
 * emit-side hardening.
 */
export interface EventPayloads {
  [POLICY_DENY]: ThreatSignalPayload;
  [AUTH_INVALID_TOKEN]: ThreatSignalPayload;
  [HONEYPOT_TRIGGER]: ThreatSignalPayload;
  [MFA_FAILED]: ThreatSignalPayload;
  [MFA_RATE_LIMITED]: ThreatSignalPayload;
  [MFA_ENROLLMENT_RESET]: ThreatSignalPayload;
  [MFA_ENROLLMENT_CONFIRMED]: ThreatSignalPayload;
  [MFA_INFRA_ERROR]: ThreatSignalPayload;
  [MFA_SECRET_DECRYPT_FAILED]: ThreatSignalPayload;
  [AUDIT_SIGNAL]: ThreatSignalPayload;
  [FINGERPRINT_BLACKLIST_SIZE_CHANGED]: FingerprintBlacklistSizeChangedPayload;
  [FINGERPRINT_DRIFT_DETECTED]: Record<string, never>;
  [AUTH_TOKEN_REVOKED]: Record<string, never>;
  [AUDIT_RECORD_FAILED]: void;
}

@Injectable()
export class TypedEvents {
  constructor(private readonly bus: EventEmitter2) {}

  emit<E extends keyof EventPayloads>(
    event: E,
    ...args: EventPayloads[E] extends void ? [] : [EventPayloads[E]]
  ): void {
    this.bus.emit(event, ...args);
  }
}
