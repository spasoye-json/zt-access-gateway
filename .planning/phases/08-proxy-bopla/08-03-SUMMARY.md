---
phase: 08-proxy-bopla
plan: "03"
subsystem: bopla-interceptor
tags:
  - bopla
  - field-stripping
  - role-based
  - tdd-green
dependency_graph:
  requires:
    - "08-00: field-policy.json schema + BoPlaInterceptor RED stub"
  provides:
    - "BoPlaInterceptor: role-based recursive JSON field stripping"
    - "FieldPolicy: TypeScript interface for policy file schema"
  affects:
    - "08-04: ProxyModule exports BoPlaInterceptor for GatewayMiddleware consumption"
tech_stack:
  added:
    - micromatch (glob path matching for policy rules)
  patterns:
    - "Direct instantiation in unit tests (no TestingModule)"
    - "onModuleInit loads field-policy.json once; strip() is pure per-call"
key_files:
  created:
    - src/proxy/interfaces/field-policy.interface.ts
    - src/proxy/bopla.interceptor.ts
  modified:
    - src/proxy/__tests__/bopla.interceptor.spec.ts
decisions:
  - "admin role always allowed regardless of policy (fail-open for admin, fail-closed for unknown)"
  - "unknown roles return {} (fail-closed default, BOPL-04)"
  - "recursive walk applies allowList at each nesting level — nested objects not granted by parent key"
  - "policy loaded at onModuleInit, not per-request — policy path from AppConfigService"
metrics:
  duration: "~8 minutes"
  tests_added: 17
  tests_green: 17
requirements_covered:
  - BOPL-01
  - BOPL-02
  - BOPL-03
  - BOPL-04
---

## What Was Built

`BoPlaInterceptor` — role-based JSON field stripping for BOPLA (Broken Object Property Level Authorization). Loads `policy/field-policy.json` at module init; on each `strip(data, path, roles)` call walks the JSON recursively and returns only the fields the caller's highest-privilege role is allowed to see.

## Self-Check: PASSED

- [x] `src/proxy/bopla.interceptor.ts` — BoPlaInterceptor with onModuleInit + strip() + recursive applyAllowList
- [x] `src/proxy/interfaces/field-policy.interface.ts` — FieldPolicy type alias
- [x] `src/proxy/__tests__/bopla.interceptor.spec.ts` — 17 GREEN tests
- [x] TDD: RED commit (`test(08-03): add failing tests for BoPlaInterceptor`) → GREEN commit (`feat(08-03): implement BoPlaInterceptor`)
- [x] `npx tsc --noEmit` exits 0

## Key Deviations

None — implemented exactly as planned.
