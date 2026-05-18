#!/usr/bin/env bash
# Scenario 6 — BOPLA response field stripping (PRD #1 user story 20, issue #8).
#
# Self-contained: mints Alice's JWT, fires GET /users/u-1 with
# x-demo-trust-score: 0.2, prints the response body, exits non-zero on any
# mismatch (status != 200, or ssn / internalRiskScore present in the body).

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
TARGET_PATH="${TARGET_PATH:-/users/u-1}"
TRUST_OVERRIDE="${TRUST_OVERRIDE:-0.2}"

fail() {
  echo "scenario-6: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

# 1) Mint Alice's JWT (roles=user).
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

# 2) Fire the request. Expect 200 and a stripped body.
RESP="$(mktemp)"
trap 'rm -f "${RESP}"' EXIT
CODE="$(curl -sS -o "${RESP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${TRUST_OVERRIDE}")"
echo "GET ${TARGET_PATH} (x-demo-trust-score: ${TRUST_OVERRIDE}) → ${CODE}"
cat "${RESP}"; echo

[[ "${CODE}" == "200" ]] || fail "expected 200, got ${CODE}"

# 3) Body must parse as JSON and must NOT contain ssn or internalRiskScore.
jq -e . "${RESP}" >/dev/null 2>&1 || fail "response body is not valid JSON"

if jq -e 'has("ssn")' "${RESP}" >/dev/null; then
  fail "expected ssn to be stripped, but it is present in the body"
fi
if jq -e 'has("internalRiskScore")' "${RESP}" >/dev/null; then
  fail "expected internalRiskScore to be stripped, but it is present in the body"
fi

echo "scenario-6: OK (ssn + internalRiskScore stripped by BOPLA)"
