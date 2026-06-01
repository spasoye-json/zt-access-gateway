#!/usr/bin/env bash
# Scenario 2 — rejected credentials → 401.
#
# Consolidates every identity-layer rejection the gateway must enforce before a
# request is ever scored or authorized:
#   2a) No Authorization header                  → 401 (auth stage).
#   2b) Well-formed JWT, wrong signature         → 401 (auth stage).
#   2c) Valid JWT, then self-revoked via          → 401 token_revoked
#       POST /auth/revoke, then replayed            (revocation stage).
#
# Self-contained. Exits non-zero on any mismatch.

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
REPLAY_PATH="${REPLAY_PATH:-/orders/echo}"

fail() {
  echo "scenario-2: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

# 2a) No Authorization header → 401.
CODE_2A="$(curl -sS -o "${TMP}" -w '%{http_code}' "${GATEWAY}${TARGET_PATH}")"
echo "2a: GET ${TARGET_PATH} (no Authorization) → ${CODE_2A}"
[[ "${CODE_2A}" == "401" ]] || fail "expected 401 without Authorization, got ${CODE_2A}"

# 2b) Bad JWT (well-formed shape, wrong signature) → 401.
# Minted at runtime with a deliberately wrong HS256 secret so no JWT-shaped
# literal lives in the source (avoids tripping JWT secret-detectors like
# GitGuardian on a token that is by-design unverifiable).
BAD_TOKEN="$(JWT_SECRET='this-secret-is-not-the-real-one-32chars-pad!' SUB=alice ROLES=user \
  node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint wrong-secret JWT"
[[ -n "${BAD_TOKEN}" ]] || fail "minted bad JWT is empty"
CODE_2B="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${BAD_TOKEN}")"
echo "2b: GET ${TARGET_PATH} (bad signature) → ${CODE_2B}"
[[ "${CODE_2B}" == "401" ]] || fail "expected 401 with bad JWT, got ${CODE_2B}"

# 2c) Valid JWT → self-revoke → replay → 401 token_revoked.
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

# Decode jti + exp from the JWT payload (the revoke endpoint needs both).
b64url_decode() {
  local data="${1//-/+}"
  data="${data//_/\/}"
  local pad=$(( 4 - ${#data} % 4 ))
  if (( pad < 4 )); then data+="$(printf '=%.0s' $(seq 1 $pad))"; fi
  printf '%s' "$data" | base64 -d 2>/dev/null
}
PAYLOAD_JSON="$(b64url_decode "$(printf '%s' "${TOKEN}" | cut -d. -f2)")"
JTI="$(printf '%s' "${PAYLOAD_JSON}" | jq -r '.jti')"
EXP="$(printf '%s' "${PAYLOAD_JSON}" | jq -r '.exp')"
[[ "${JTI}" != "null" && -n "${JTI}" ]] || fail "could not extract jti from JWT"
[[ "${EXP}" != "null" && -n "${EXP}" ]] || fail "could not extract exp from JWT"

REVOKE_CODE="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  -X POST "${GATEWAY}/auth/revoke" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --arg jti "${JTI}" --argjson exp "${EXP}" '{jti:$jti, exp:$exp}')")"
echo "2c: POST /auth/revoke → ${REVOKE_CODE}"
[[ "${REVOKE_CODE}" == "200" ]] || fail "expected 200 from /auth/revoke, got ${REVOKE_CODE}"

REPLAY_CODE="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${REPLAY_PATH}" \
  -H "Authorization: Bearer ${TOKEN}")"
echo "2c: GET ${REPLAY_PATH} (replay revoked token) → ${REPLAY_CODE}"
cat "${TMP}"; echo
[[ "${REPLAY_CODE}" == "401" ]] || fail "expected 401 on replay, got ${REPLAY_CODE}"
[[ "$(jq -r '.error // empty' "${TMP}")" == "token_revoked" ]] \
  || fail "expected body.error=token_revoked on replay"

echo "scenario-2: OK (no-auth 401 → bad-sig 401 → revoked 401)"
