# Trust signal history persisted only after a successful ALLOW

The persisted device/IP/score history (`trust_signals` / `trust_activity`) is written **only** after a request reaches ALLOW *and* the downstream proxy returns success — never on CHALLENGE or DENY. Recording on CHALLENGE would let an attacker farm reputation by repeatedly triggering challenges they never complete, manufacturing favourable history without ever proving themselves.

> Terminology: this is the *stored output* "trust context", distinct from the per-request scoring *input* also called **Trust Context** in [CONTEXT.md](../../CONTEXT.md). See the flagged ambiguity there.

## Consequences

- A request that is challenged or denied leaves no reputational trace — cold-start users build trust only through completed, allowed requests.
- The write happens late in the pipeline (post-proxy), so it must tolerate the proxy having already responded.
