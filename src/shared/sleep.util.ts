/**
 * Async sleep — yields the event loop so other requests are not blocked (D-05).
 * Used by Ja4hMiddleware for tarpit delays on blacklisted fingerprints.
 */
export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Returns a random integer millisecond value in [minMs, maxMs).
 * Used to vary tarpit delay so response timing cannot be used to fingerprint the gateway.
 */
export const randomDelay = (minMs: number, maxMs: number): number =>
  Math.floor(Math.random() * (maxMs - minMs)) + minMs;
