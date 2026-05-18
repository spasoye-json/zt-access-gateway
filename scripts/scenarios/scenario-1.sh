#!/usr/bin/env bash
# Scenario 1 — happy path (PRD #1 user story 20, issue #9).
#
# Self-contained: mints Alice's JWT, fires GET /orders/o-1 with
# x-demo-trust-score: 0.0 so the policy lands ALLOW deterministically.
# Asserts 200 and the deterministic orders body. Exits non-zero on any
# mismatch.

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
TARGET_PATH="${TARGET_PATH:-/orders/o-1}"
TRUST_OVERRIDE="${TRUST_OVERRIDE:-0.0}"

fail() {
  echo "scenario-1: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

# 1) Mint Alice's JWT (roles=user).
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

# 2) Fire the request. Expect 200 + deterministic body.
RESP="$(mktemp)"
trap 'rm -f "${RESP}"' EXIT

START_NS="$(date +%s%N)"
CODE="$(curl -sS -o "${RESP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${TRUST_OVERRIDE}")"
END_NS="$(date +%s%N)"
LATENCY_MS=$(( (END_NS - START_NS) / 1000000 ))

echo "GET ${TARGET_PATH} (x-demo-trust-score: ${TRUST_OVERRIDE}) → ${CODE} in ${LATENCY_MS}ms"
cat "${RESP}"; echo

[[ "${CODE}" == "200" ]] || fail "expected 200, got ${CODE}"

jq -e . "${RESP}" >/dev/null 2>&1 || fail "response body is not valid JSON"

# 3) Body must match the deterministic shape returned by orders-service.
ID="$(jq -r '.id // empty' "${RESP}")"
AMOUNT="$(jq -r '.amount // empty' "${RESP}")"
CURRENCY="$(jq -r '.currency // empty' "${RESP}")"
[[ "${ID}" == "o-1" ]]      || fail "expected id=o-1, got '${ID}'"
[[ "${AMOUNT}" == "99" ]]   || fail "expected amount=99, got '${AMOUNT}'"
[[ "${CURRENCY}" == "USD" ]] || fail "expected currency=USD, got '${CURRENCY}'"

echo "scenario-1: OK (${LATENCY_MS}ms)"
