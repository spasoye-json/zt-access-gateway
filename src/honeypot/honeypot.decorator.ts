import { SetMetadata } from '@nestjs/common';

/**
 * Metadata key used to mark a controller method as a honeypot handler.
 * Phase 2: metadata-only — the handler itself executes the trap sequence inline.
 * Future phases may use this key in a guard/interceptor to enforce behaviour centrally.
 */
export const HONEYPOT_KEY = 'isHoneypot';

/**
 * @Honeypot() — marks a route handler as a decoy trap.
 * Sets HONEYPOT_KEY metadata to true on the decorated method.
 */
export const Honeypot = () => SetMetadata(HONEYPOT_KEY, true);
