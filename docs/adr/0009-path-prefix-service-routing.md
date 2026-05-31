# Proxy target chosen by path prefix, validated against the service registry

The downstream service is selected from the first segment of the request path (`/users/123` → `users`), looked up in the service registry, and forwarded with the segment stripped. The target is **never** taken from a client-controllable source like the `Host` header or an `X-Target-Service` header — those are SSRF vectors (an attacker sets `Host: internal-admin.svc`). The registry is the allowlist: a name not in it is never contacted, and resolved IPs are re-checked against private/metadata ranges (DNS-rebinding guard).

Mechanics: [HARDENING_ARCHITECTURE.md §8](../HARDENING_ARCHITECTURE.md#8-ssrf-and-dns-rebinding-protection).

## Consequences

- Adding a downstream service means adding a registry entry, not a routing rule.
- Path-prefix routing is the primary SSRF control; the IP-range/DNS checks are defence in depth.
