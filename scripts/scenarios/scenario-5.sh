#!/usr/bin/env bash
# Scenario 5 — revoked token replay (PRD #1 user story 20, issue #7).
#
# Self-contained: mints Alice's JWT, calls POST /auth/revoke with that JWT
# (asserts 200), replays the same JWT against a protected endpoint
# (asserts 401 + error=token_revoked). Exits non-zero on any mismatch.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Load .env.demo so JWT_SECRET, PORT, etc. are available.
if [[ -f "${REPO_ROOT}/.env.demo" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_ROOT}/.env.demo"
  set +a
fi

GATEWAY="${GATEWAY_URL:-http://localhost:${PORT:-3000}}"
REPLAY_PATH="${REPLAY_PATH:-/orders/echo}"

fail() {
  echo "scenario-5: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

# 1) Mint Alice's JWT.
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

# 2) Decode jti + exp from the JWT payload.
b64url_decode() {
  local data="${1//-/+}"
  data="${data//_/\/}"
  local pad=$(( 4 - ${#data} % 4 ))
  if (( pad < 4 )); then data+="$(printf '=%.0s' $(seq 1 $pad))"; fi
  printf '%s' "$data" | base64 -d 2>/dev/null
}

PAYLOAD_B64="$(printf '%s' "${TOKEN}" | cut -d. -f2)"
PAYLOAD_JSON="$(b64url_decode "${PAYLOAD_B64}")"
JTI="$(printf '%s' "${PAYLOAD_JSON}" | jq -r '.jti')"
EXP="$(printf '%s' "${PAYLOAD_JSON}" | jq -r '.exp')"
[[ "${JTI}" != "null" && -n "${JTI}" ]] || fail "could not extract jti from JWT"
[[ "${EXP}" != "null" && -n "${EXP}" ]] || fail "could not extract exp from JWT"

# 3) Self-revoke via the production endpoint. Expect 200.
REVOKE_RESP="$(mktemp)"
trap 'rm -f "${REVOKE_RESP}"' EXIT
REVOKE_CODE="$(curl -sS -o "${REVOKE_RESP}" -w '%{http_code}' \
  -X POST "${GATEWAY}/auth/revoke" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --arg jti "${JTI}" --argjson exp "${EXP}" '{jti:$jti, exp:$exp}')")"
echo "POST /auth/revoke → ${REVOKE_CODE}"
cat "${REVOKE_RESP}"; echo
[[ "${REVOKE_CODE}" == "200" ]] || fail "expected 200 from /auth/revoke, got ${REVOKE_CODE}"

# 4) Replay the now-revoked JWT against a protected endpoint. Expect 401 + token_revoked.
REPLAY_RESP="$(mktemp)"
trap 'rm -f "${REVOKE_RESP}" "${REPLAY_RESP}"' EXIT
REPLAY_CODE="$(curl -sS -o "${REPLAY_RESP}" -w '%{http_code}' \
  "${GATEWAY}${REPLAY_PATH}" \
  -H "Authorization: Bearer ${TOKEN}")"
echo "GET ${REPLAY_PATH} (replay) → ${REPLAY_CODE}"
cat "${REPLAY_RESP}"; echo
[[ "${REPLAY_CODE}" == "401" ]] || fail "expected 401 on replay, got ${REPLAY_CODE}"

REPLAY_ERROR="$(jq -r '.error // empty' "${REPLAY_RESP}")"
[[ "${REPLAY_ERROR}" == "token_revoked" ]] \
  || fail "expected body.error=token_revoked on replay, got '${REPLAY_ERROR}'"

echo "scenario-5: OK"
