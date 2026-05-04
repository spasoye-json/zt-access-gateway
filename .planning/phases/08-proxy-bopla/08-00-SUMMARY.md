---
phase: 08-proxy-bopla
plan: "00"
subsystem: proxy-config
tags:
  - opossum
  - circuit-breaker
  - bopla
  - config
  - tdd-red
dependency_graph:
  requires:
    - "07-*: MFA challenge (config.service.ts Phase 7 block)"
  provides:
    - "opossum dependency + CJS transform fix"
    - "policy/field-policy.json starter BOPLA policy"
    - "6 Phase 8 Joi validation entries"
    - "6 AppConfigService typed getters"
    - "express.d.ts proxyTarget + boPlaStripped fields"
    - "5 RED test stubs (60 it.todo) for Waves 1-3"
  affects:
    - "08-01..08-04: will implement against these contracts"
tech_stack:
  added:
    - "opossum@9.0.0 (circuit breaker)"
    - "@types/opossum@8.1.9"
    - "@types/micromatch@4.0.10"
  patterns:
    - "Jest transformIgnorePatterns exclusion for opossum CJS interop (Pitfall 1)"
    - "Wave 0 RED stubs: describe/it.todo only, zero src/proxy/* imports"
key_files:
  created:
    - policy/field-policy.json
    - src/proxy/__tests__/service-registry.service.spec.ts
    - src/proxy/__tests__/dns-rebinding.guard.spec.ts
    - src/proxy/__tests__/response-validator.spec.ts
    - src/proxy/__tests__/proxy.service.spec.ts
    - src/proxy/__tests__/bopla.interceptor.spec.ts
  modified:
    - package.json
    - package-lock.json
    - src/config/config.module.ts
    - src/config/config.service.ts
    - src/shared/express.d.ts
    - .env.example
decisions:
  - "opossum added to transformIgnorePatterns to prevent 'not a constructor' Jest failure (Pitfall 1)"
  - "field-policy.json committed at policy/ alongside model.conf + policy.csv (policy-as-code, D-05)"
  - "PROXY_SERVICE_REGISTRY validated as Joi.string().required() — structural JSON validation deferred to ServiceRegistryService.onModuleInit (Wave 1)"
  - "Wave 0 stubs contain zero src/proxy/* imports to avoid TS compile breakage before implementation exists"
metrics:
  duration: "~5 minutes"
  completed_date: "2026-05-04"
  tasks_completed: 3
  files_changed: 11
---

# Phase 8 Plan 00: Wave 0 RED Setup Summary

Wave 0 RED scaffolding: opossum circuit-breaker dependency installed, field-policy.json BOPLA starter policy shipped, 6 Phase 8 Joi/config entries added, express.d.ts augmented, and 5 failing test stub files (60 `it.todo`) established as locked contracts for Waves 1–3.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Install opossum + types, patch transformIgnorePatterns, ship field-policy.json, document env vars | 7deb2f2 | package.json, package-lock.json, policy/field-policy.json, .env.example |
| 2 | Add Phase 8 Joi schema, AppConfigService getters, express.d.ts augmentation | 8e02309 | src/config/config.module.ts, src/config/config.service.ts, src/shared/express.d.ts |
| 3 | Create 5 RED test stubs (60 it.todo, zero real it() calls) | 1192024 | src/proxy/__tests__/*.spec.ts (5 files) |

## What Was Built

### Dependencies
- `opossum@9.0.0` installed as production dependency (circuit breaker for ProxyService)
- `@types/opossum@8.1.9` + `@types/micromatch@4.0.10` installed as devDependencies
- `transformIgnorePatterns` patched to add `opossum` exclusion (prevents `TypeError: CircuitBreaker is not a constructor` in ts-jest)

### BOPLA Starter Policy
`policy/field-policy.json` ships with D-06 schema covering 3 demo microservices:
- `/users/**`: admin all fields, user sees id/email/name
- `/orders/**`: admin all fields, user sees id/status/total
- `/billing/**`: admin-only (no user fields)

### Config Extension
6 new Joi validation entries in `config.module.ts`:
- `PROXY_SERVICE_REGISTRY`: required string (JSON parsed by ServiceRegistryService)
- `PROXY_CB_VOLUME_THRESHOLD`: default 5
- `PROXY_CB_ERROR_THRESHOLD`: default 50 (%)
- `PROXY_CB_RESET_TIMEOUT`: default 10000 (ms)
- `PROXY_MAX_RETRIES`: default 3
- `BOPLA_POLICY_PATH`: default `policy/field-policy.json`

6 typed getters in `AppConfigService`: `proxyServiceRegistry`, `proxyCbVolumeThreshold`, `proxyCbErrorThreshold`, `proxyCbResetTimeout`, `proxyMaxRetries`, `boplaPolicyPath`.

### Express.d.ts Augmentation
Two new optional fields on Express.Request:
- `proxyTarget?: string` — service name extracted by ProxyService
- `boPlaStripped?: boolean` — true when BOPLA stripped fields from response

### RED Test Stubs
5 spec files with 60 `it.todo` assertions covering all PRXY-* and BOPL-* requirements:

| File | Requirements | it.todo count |
|------|-------------|---------------|
| service-registry.service.spec.ts | PRXY-03, PRXY-06 | 8 |
| dns-rebinding.guard.spec.ts | PRXY-07, PRXY-08 | 8 |
| response-validator.spec.ts | PRXY-09 | 6 |
| proxy.service.spec.ts | PRXY-01, PRXY-02, PRXY-04, PRXY-05 | 23 |
| bopla.interceptor.spec.ts | BOPL-01, BOPL-02, BOPL-03, BOPL-04 | 15 |

## Verification

All plan verification checks passed:
- `node -e "require('opossum')"` exits 0
- `policy/field-policy.json` exists with correct schema
- `PROXY_SERVICE_REGISTRY` present in config.module.ts Joi schema
- `proxyServiceRegistry` getter present in config.service.ts
- `proxyTarget` + `boPlaStripped` present in express.d.ts
- `npx tsc --noEmit` exits 0
- `npx jest src/proxy/__tests__/ --passWithNoTests` exits 0 (60 todo, 0 failed)

## Deviations from Plan

None — plan executed exactly as written.

The worktree lacked its own `node_modules`. Applied standard pattern: symlinked main repo's `node_modules` into worktree (npm installs run against the main repo, symlink provides access in worktree context). This is consistent with the worktree-based parallel execution approach.

## Known Stubs

The 5 test files contain only `it.todo()` stubs by design — this is the intended Wave 0 RED state. All stubs will be filled in Waves 1–3 (plans 08-01 through 08-04).

## Threat Flags

No new network endpoints or auth paths introduced in this plan. `policy/field-policy.json` contains schema only (no secrets) — per T-08-00-02 disposition: accept (documented in plan threat register).

## Self-Check: PASSED

- `policy/field-policy.json`: FOUND
- `src/proxy/__tests__/service-registry.service.spec.ts`: FOUND
- `src/proxy/__tests__/dns-rebinding.guard.spec.ts`: FOUND
- `src/proxy/__tests__/response-validator.spec.ts`: FOUND
- `src/proxy/__tests__/proxy.service.spec.ts`: FOUND
- `src/proxy/__tests__/bopla.interceptor.spec.ts`: FOUND
- commit 7deb2f2: FOUND
- commit 8e02309: FOUND
- commit 1192024: FOUND
