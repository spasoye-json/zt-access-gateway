# Circuit breaker wraps the full retry loop, not individual attempts

The `opossum` circuit breaker fires once per proxied request around the *entire* retry chain, so the breaker records a single failure only after all retries are exhausted — not one probe per attempt. Wrapping individual attempts would let ordinary transient blips (which retries are meant to absorb) rack up failures and trip the breaker prematurely, turning a recoverable hiccup into an outage. Breakers are per-service, so one flaky downstream can't trip the gateway globally.

Mechanics: [HARDENING_ARCHITECTURE.md §8](../HARDENING_ARCHITECTURE.md#8-ssrf-and-dns-rebinding-protection) (proxy module).

## Consequences

- Breaker failure counts reflect genuinely-failed requests, not retried attempts.
- Per-service breakers are initialized eagerly from the service registry at startup.
