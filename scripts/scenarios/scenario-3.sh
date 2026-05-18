#!/usr/bin/env bash
# Scenario 3 — honeypot (PRD #1 user story 20, issue #9).
#
# Self-contained: fires GET /.env (a registered honeypot decoy path) with
# no Authorization header at all — honeypot routes are deliberately
# unauthenticated to keep scanners engaged. Asserts:
#   - status 200 (the deceptive fake response)
#   - body contains the canary marker (proves we hit the trap, not a real route)
#   - end-to-end latency well under 1s (DEMO_MODE tarpit cap is 50ms)
#
# Exits non-zero on any mismatch.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -f "${REPO_ROOT}/.env.demo" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_ROOT}/.env.demo"
  set +a
fi

GATEWAY="${GATEWAY_URL:-http://localhost:${PORT:-3000}}"
TARGET_PATH="${TARGET_PATH:-/.env}"
LATENCY_BUDGET_MS="${LATENCY_BUDGET_MS:-1000}"

fail() {
  echo "scenario-3: $*" >&2
  exit 1
}

RESP="$(mktemp)"
trap 'rm -f "${RESP}"' EXIT

START_NS="$(date +%s%N)"
CODE="$(curl -sS -o "${RESP}" -w '%{http_code}' "${GATEWAY}${TARGET_PATH}")"
END_NS="$(date +%s%N)"
LATENCY_MS=$(( (END_NS - START_NS) / 1000000 ))

echo "GET ${TARGET_PATH} → ${CODE} in ${LATENCY_MS}ms"
cat "${RESP}"; echo

# Shadow controller returns 200 with a realistic fake body to keep scanners engaged.
[[ "${CODE}" == "200" ]] || fail "expected 200 from honeypot, got ${CODE}"

# Canary marker — /.env decoy body contains AKIAIOSFODNN7EXAMPLE.
grep -q 'AKIAIOSFODNN7EXAMPLE' "${RESP}" \
  || fail "honeypot body did not contain expected canary marker"

# DEMO_MODE tarpit caps at 50ms; even with cold boot we must finish well under 1s.
if (( LATENCY_MS >= LATENCY_BUDGET_MS )); then
  fail "honeypot took ${LATENCY_MS}ms — expected < ${LATENCY_BUDGET_MS}ms under DEMO_MODE tarpit cap"
fi

echo "scenario-3: OK (honeypot tripped in ${LATENCY_MS}ms)"
