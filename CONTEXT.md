# Zero-Trust Access Gateway

The gateway is the single ingress point that authenticates, scores, and authorises every request before it reaches a downstream microservice. This document fixes the vocabulary the team and its agents use when talking about that pipeline.

## Language

### Trust scoring

**Trust Signal**:
A single contribution to the aggregate trust score, expressed as a `SignalAdjustment` value (`{ source, delta, reason, decayable }`). Signals are summed (around a 0.5 base) and clamped to `[0, 1]` to produce the score.
_Avoid_: factor, indicator, feature.

**Signal Rule**:
A data row in `SIGNAL_RULES` that produces a Trust Signal via a numeric repository query compared against a threshold. Used for the uniform shape "query → compare → ± delta." Adding a new rule is a row, not a class.
_Avoid_: scoring rule, threshold check, heuristic.

**Trust Signal Provider**:
A class that produces a Trust Signal via custom logic that does not fit a Signal Rule's shape — currently `Ja4hDriftProvider` (string equality + event emission) and `BehaviorAnomalyProvider` (statistical z-scores with warmup).
_Avoid_: scorer, signal class.

**Trust Decay**:
A post-processor that runs after Signal Rules and Trust Signal Providers, attenuating any Trust Signal whose `decayable` flag is true and whose `delta` is favourable (negative), based on idle time since `last_seen_at`. Produces a single corrective Trust Signal.
_Avoid_: trust expiry, time decay, decay provider.

**Trust Context**:
The per-request input to trust scoring: user id, device id, IP, JA4H fingerprint, request timestamp. Built once in the trust-score stage; consumed by every Rule, Provider, and Decay.
_Avoid_: scoring context, request context (the latter means something else — see below).

### Pipeline

**Stage**:
A single step in the gateway pipeline implementing `PipelineStage.run(ctx)` and returning a `StageOutcome`. Stages communicate only via `StageContext` and the outcome discriminated union — never by writing to `res` directly.
_Avoid_: middleware, step, phase.

**StageContext**:
The mutable object threaded through every Stage. Holds the request, response, and progressively-populated fields (`claims`, `trustScore`, `policyDecision`, …) accumulated as the pipeline runs.
_Avoid_: request context (ambiguous), pipeline state.

**Policy Decision**:
The value `PolicyEvaluatorService.evaluate` returns: `{ decision: ALLOW | CHALLENGE | DENY, reason, score?, matchedSubject? }`. Stored on `StageContext.policyDecision` and consumed by downstream Stages.
_Avoid_: authorisation result, verdict.

**Auth Outcome**:
The discriminated union `AuthService.authenticate` returns: `{ kind: 'ok', claims }` | `{ kind: 'invalid', reason, message? }` | `{ kind: 'revoked' }`. Owns header parsing, scheme check, signature verification, and revocation lookup as one indivisible answer to "is this token usable right now?". Consumed by exactly two adapters — `AuthStage` (maps to `StageOutcome`) and `JwtAuthGuard` (maps to `UnauthorizedException`). Adapters share one emission helper so `AUTH_INVALID_TOKEN` payloads stay identical across seams.
_Avoid_: auth result, validation result.

**Stage Outcome**:
The discriminated union a Stage returns: `continue`, `bypass`, `short-circuit`, `proxied`. The orchestrator advances on `continue` and terminates the pipeline otherwise.
_Avoid_: result, return code.

### Decisions & escalation

**Decision**:
The three-way outcome the gateway reaches for a request: **ALLOW**, **CHALLENGE**, or **DENY**. ALLOW proceeds to the proxy; CHALLENGE demands further proof (hashcash and/or MFA) before it can become ALLOW; DENY is terminal. Carried as **Policy Decision** on `StageContext` (see above).
_Avoid_: verdict, result, judgement.

**Threat Level**:
A gateway-wide posture — **Normal**, **Elevated**, or **Critical** — that auto-tightens policy thresholds once accumulated Threat Signals cross configured counts, then decays on cooldown. Global, not per-IP or per-user.
_Avoid_: alert level, severity.

**Threat Signal**:
A security-relevant *event* (a policy DENY, an invalid token, a failed MFA, a honeypot trigger) fed to the threat-escalation aggregator. Distinct from a **Trust Signal**, which scores one request's risk; a Threat Signal accumulates across requests to raise the Threat Level.
_Avoid_: event, alert, trust signal.

### Identity & fingerprinting

**JA4H Fingerprint**:
A hash of a client's raw HTTP header ordering and casing, identifying the actual HTTP library rather than a spoofable User-Agent string. The gateway's primary stable client identity, attached to the request before auth.
_Avoid_: client hash, UA fingerprint.

**Claims**:
The validated payload extracted from a request's Bearer JWT (`userId`, `roles`, `deviceId`, `jti`, …). `deviceId` is mandatory — auth fails if it is absent, since trust scoring and MFA binding both depend on a stable device identity. The `UserClaims` shape.
_Avoid_: token payload, principal, identity.

**JTI**:
The unique-ID claim of a JWT. The unit of token revocation: a revoked JTI is rejected until the token's own expiry, then forgotten.
_Avoid_: token id, session id.

### Defenses

**Honeypot Decoy**:
A fake route (e.g. `/.env`, `/wp-login.php`) absent from the real API. Legitimate clients never hit one, so any hit is a guaranteed attacker — it terminally blacklists the JA4H Fingerprint and returns a fake payload.
_Avoid_: trap, fake endpoint, canary route.

**Fingerprint Blacklist**:
The set of JA4H Fingerprints denied entry. An entry is either **terminal** (from a Honeypot Decoy hit — never recovers) or time-bounded (from threat escalation).
_Avoid_: ban list, blocklist.

**Tarpit**:
A deliberate delay before responding to a blacklisted or honeypot request, to waste an attacker's time. Not a rate limiter.
_Avoid_: throttle, slowdown.

**Hashcash**:
A proof-of-work puzzle the gateway demands from high-risk requests: solve a SHA-256 **Challenge** whose difficulty scales with the trust score. Imposes an economic cost on bots; milliseconds for a real browser. Stateless and identity-bound (see [ADR-0007](./docs/adr/0007-stateless-hashcash-nonce.md)).
_Avoid_: proof of work (in prose), captcha.

**MFA Challenge**:
The CHALLENGE-to-ALLOW step-up: the gateway requires a valid **MFA Token** to promote a CHALLENGE Decision to ALLOW. Not to be confused with a hashcash **Challenge**.
_Avoid_: 2FA prompt, OTP request.

**MFA Token**:
A short-lived JWT issued after successful MFA, bound to `userId|deviceId|ip` and signed with a secret distinct from the session JWT secret (see [ADR-0003](./docs/adr/0003-mfa-token-fingerprint-binding.md), [ADR-0006](./docs/adr/0006-separate-mfa-jwt-secret.md)). Presenting a valid one promotes CHALLENGE → ALLOW.
_Avoid_: MFA cookie, step-up token.

**BOPLA Stripping**:
Role-based removal of unauthorized fields from a downstream response *at the gateway*, so a backend that over-returns fields can't leak them. Named for OWASP API3:2023 (Broken Object Property Level Authorization).
_Avoid_: field filtering, redaction, masking.

### Forwarding & gating

**Bypass Set / Auth-Only Set**:
The two path allowlists checked before the pipeline runs. The **bypass set** (`/health`, `/metrics`) skips the pipeline entirely; the **auth-only set** (`/auth/revoke`, `/mfa/*`, `/audit/logs`, `/policy/admin/*`) runs auth + revocation but not the full risk pipeline.
_Avoid_: public routes, whitelist.

**Service Registry**:
The allowlist of downstream services (name → base URL) the proxy may forward to — the SSRF boundary. A target absent from the registry is never contacted. The target service is chosen by the request's path prefix, never a client-supplied header (see [ADR-0009](./docs/adr/0009-path-prefix-service-routing.md)).
_Avoid_: upstream list, service catalog, routing table.

**Audit-Before-Allow**:
The write-ahead-log discipline: an ALLOW is blocked until its audit entry is durably written; if the write is exhausted, the request is denied rather than served unaudited (see [ADR-0001](./docs/adr/0001-audit-before-allow-wal.md)).
_Avoid_: audit logging (the async act).

## Relationships

- A **Trust Context** is the input to every **Signal Rule**, **Trust Signal Provider**, and **Trust Decay**.
- **Signal Rules** and **Trust Signal Providers** each produce one **Trust Signal**.
- **Trust Decay** consumes all **Trust Signals** from one request and produces one corrective **Trust Signal** of its own.
- The sum of all **Trust Signals** (clamped to `[0, 1]` around a 0.5 base) is the trust score on `StageContext.trustScore`.
- A **Policy Decision** is computed from the trust score plus Casbin rules; thresholds map score bands to `ALLOW | CHALLENGE | DENY`.
- Every **Stage** reads and writes the same **StageContext** and returns a **Stage Outcome**.
- `AuthStage` and `JwtAuthGuard` are the only callers of `AuthService.authenticate`; both consume the same **Auth Outcome** and emit `AUTH_INVALID_TOKEN` via the shared `buildAuthInvalidPayload` helper.
- A **Policy Decision** of CHALLENGE is promoted to ALLOW only by a valid **MFA Token**; **Hashcash** gates high-risk requests *earlier* in the pipeline, before policy evaluation.
- A **Honeypot Decoy** hit adds a **terminal** entry to the **Fingerprint Blacklist**; **threat escalation** adds time-bounded ones. A blacklisted **JA4H Fingerprint** is rejected (after a **Tarpit**) before trust scoring runs.
- **Threat Signals** accumulate across requests to raise the **Threat Level**, which tightens the thresholds a **Policy Decision** uses — the feedback loop from past requests onto future ones.
- The **Service Registry** is the SSRF boundary for the proxy; only an ALLOW that clears **Audit-Before-Allow** reaches it, and its response is **BOPLA-stripped** before returning to the client.

## Example dialogue

> **Dev:** "We want to add a geolocation check that nudges the score up when the IP is from a new country. Is that a Signal Rule or a Trust Signal Provider?"
>
> **Domain expert:** "It's a query against a repo, compared to a threshold ('how many prior allows from this country?'), with ± deltas. That's the Signal Rule shape — add a row in `SIGNAL_RULES`, don't write a new class."
>
> **Dev:** "And should the favourable delta decay over time?"
>
> **Domain expert:** "Yes — historical favourable signals always decay, otherwise old trust never rots. Set `decayable: true` on the row. Trust Decay will attenuate it automatically once `idleMs` grows past the half-life."
>
> **Dev:** "What about a Trust Signal that emits a metric when it fires?"
>
> **Domain expert:** "That's not Signal Rule shape — it's a side-effect. Write a Trust Signal Provider class. `Ja4hDriftProvider` is the precedent."

## Flagged ambiguities

- "request context" was used loosely to mean both **StageContext** (the mutable pipeline bag) and **Trust Context** (the scoring input). They are distinct: Trust Context is a strict subset projected from StageContext for the trust-score Stage.
- "provider" historically meant both Signal Rule logic and custom scoring logic. Resolved: only custom-logic scorers are **Trust Signal Providers**; the uniform threshold ones are **Signal Rules**.
- "challenge" is overloaded. A **Challenge** (hashcash) is a proof-of-work puzzle gating high-risk requests; an **MFA Challenge** is the CHALLENGE→ALLOW step-up requiring an **MFA Token**. They sit at different pipeline stages and are not interchangeable.
- "trust context" is overloaded. **Trust Context** (above) is the per-request scoring *input*. The *persisted* device/IP/score history written after a successful ALLOW — what older `.planning` notes and [ADR-0002](./docs/adr/0002-trust-context-only-on-allow.md) call "recording trust context" — is the **Trust Signal** history (`trust_signals` / `trust_activity` rows), an output. Input vs. stored output: keep them distinct.
