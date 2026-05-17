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

**Stage Outcome**:
The discriminated union a Stage returns: `continue`, `bypass`, `short-circuit`, `proxied`. The orchestrator advances on `continue` and terminates the pipeline otherwise.
_Avoid_: result, return code.

## Relationships

- A **Trust Context** is the input to every **Signal Rule**, **Trust Signal Provider**, and **Trust Decay**.
- **Signal Rules** and **Trust Signal Providers** each produce one **Trust Signal**.
- **Trust Decay** consumes all **Trust Signals** from one request and produces one corrective **Trust Signal** of its own.
- The sum of all **Trust Signals** (clamped to `[0, 1]` around a 0.5 base) is the trust score on `StageContext.trustScore`.
- A **Policy Decision** is computed from the trust score plus Casbin rules; thresholds map score bands to `ALLOW | CHALLENGE | DENY`.
- Every **Stage** reads and writes the same **StageContext** and returns a **Stage Outcome**.

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
