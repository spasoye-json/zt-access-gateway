#!/usr/bin/env bash
# Scenario 5 — policy DENY → 403 (Casbin RBAC).
#
# Demonstrates that authorization is enforced on the ACTION, not just identity.
# Alice (role:user) may GET an order but the policy grants her no DELETE on
# /orders/:id, so:
#   5a) DELETE /orders/o-1 (user, low trust) → 403 policy_denied / casbin_no_match.
#   5b) GET    /orders/o-1 (same user, same trust) → 200 — proving the denial is
#       the missing permission, not the credential.
#
# Low trust (x-demo-trust-score: 0.0) keeps the request below the hashcash
# trigger so it reaches the policy stage cleanly. Self-contained; exits non-zero
# on any mismatch.

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

fail() {
  echo "scenario-5: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

# Mint Alice's JWT (roles=user). The policy grants user GET on /orders/:id but
# no DELETE — see policy/policy.csv.
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

# 5a) Forbidden action → Casbin no-match → 403 policy_denied.
CODE_5A="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  -X DELETE "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: 0.0")"
echo "5a: DELETE ${TARGET_PATH} (user, trust 0.0) → ${CODE_5A}"
cat "${TMP}"; echo
[[ "${CODE_5A}" == "403" ]] || fail "expected 403 from policy DENY, got ${CODE_5A}"
[[ "$(jq -r '.error // empty' "${TMP}")" == "policy_denied" ]] \
  || fail "expected body.error=policy_denied on 5a"

# 5b) Permitted action, same identity → 200 (the denial was the action, not the user).
CODE_5B="$(curl -sS -o /dev/null -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: 0.0")"
echo "5b: GET ${TARGET_PATH} (same user, trust 0.0) → ${CODE_5B}"
[[ "${CODE_5B}" == "200" ]] || fail "expected 200 on the permitted GET, got ${CODE_5B}"

echo "scenario-5: OK (DELETE → 403 policy_denied; GET → 200)"
