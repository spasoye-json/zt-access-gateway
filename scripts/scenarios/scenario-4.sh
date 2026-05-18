#!/usr/bin/env bash
# Scenario 4 — high-risk request → hashcash PoW + MFA promotion (issue #9).
#
# Self-contained: mints Alice's JWT, then internally chains:
#   4a) GET /orders/o-1 with x-demo-trust-score: 0.7 (no PoW, no MFA) → 429
#       proof_of_work_required + X-Hashcash-Challenge header.
#   4b) Solve the PoW. Mint an MFA token via POST /demo/mfa-token (bypasses
#       trust + hashcash via AUTH_ONLY path). Re-issue the original request
#       with X-Hashcash-Nonce / X-Hashcash-Solution / X-MFA-Token → 200.
#
# Single command, no manual chaining. Exits non-zero on any mismatch.

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
TRUST_OVERRIDE="${TRUST_OVERRIDE:-0.7}"

fail() {
  echo "scenario-4: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

# 1) Mint Alice's JWT (roles=user). The JWT claim 'deviceId' is alice-device-1.
#    Asymmetry note: /demo/mfa-token derives deviceId from the x-device-id
#    HEADER (defaults to '' when absent), while MfaPromotionStage validates
#    against claims.deviceId from the JWT. To make the SHA-256(userId|deviceId|ip)
#    fingerprint line up, we mirror the JWT claim onto x-device-id on the mint
#    leg. The replay leg can omit it — the validator reads claims directly.
TOKEN="$(SUB=alice ROLES=user node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"
DEVICE_ID="${DEVICE_ID:-alice-device-1}"

# 4a) High-risk request without PoW headers → expect 429 + challenge.
HEADERS_4A="$(mktemp)"
BODY_4A="$(mktemp)"
trap 'rm -f "${HEADERS_4A}" "${BODY_4A}"' EXIT
CODE_4A="$(curl -sS -D "${HEADERS_4A}" -o "${BODY_4A}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${TRUST_OVERRIDE}")"
echo "GET ${TARGET_PATH} (x-demo-trust-score: ${TRUST_OVERRIDE}, no PoW) → ${CODE_4A}"
cat "${BODY_4A}"; echo
[[ "${CODE_4A}" == "429" ]] || fail "expected 429 from 4a, got ${CODE_4A}"

# Parse the X-Hashcash-Challenge header (case-insensitive grep, strip CR).
# Wire format is "<nonce>:<difficulty>" — the split below assumes ':' does not
# appear in the nonce. HashcashService emits nonce as "<base64url>.<base64url>"
# (hashcash.service.ts), and the base64url alphabet excludes ':', so the last
# ':' is unambiguously the difficulty separator.
CHALLENGE_LINE="$(grep -i '^x-hashcash-challenge:' "${HEADERS_4A}" | tr -d '\r' || true)"
[[ -n "${CHALLENGE_LINE}" ]] || fail "missing X-Hashcash-Challenge header on 4a response"
CHALLENGE_VAL="${CHALLENGE_LINE#*: }"
NONCE="${CHALLENGE_VAL%:*}"
DIFFICULTY="${CHALLENGE_VAL##*:}"
[[ -n "${NONCE}" ]] || fail "could not parse nonce from '${CHALLENGE_VAL}'"
[[ "${DIFFICULTY}" =~ ^[0-9]+$ ]] || fail "could not parse difficulty from '${CHALLENGE_VAL}'"

ERROR_4A="$(jq -r '.error // empty' "${BODY_4A}")"
[[ "${ERROR_4A}" == "proof_of_work_required" ]] \
  || fail "expected body.error=proof_of_work_required on 4a, got '${ERROR_4A}'"

echo "  challenge: nonce=${NONCE} difficulty=${DIFFICULTY}"

# 4b-i) Solve the PoW. Demo difficulty is 8 bits (≈ 256 iterations, ~ms scale)
#       because .env.demo locks HASHCASH_DIFFICULTY_MIN=HASHCASH_DIFFICULTY_MAX=8.
#       Production locks 18–22 bits (D-10), which would push the solver into
#       seconds-to-minutes territory — do NOT run this scenario against a
#       production-shaped .env or the rehearsal will stall on stage.
SOLUTION="$(node -r ts-node/register "${REPO_ROOT}/scripts/hashcash-solve.ts" "${NONCE}" "${DIFFICULTY}")" \
  || fail "hashcash solver failed"
[[ -n "${SOLUTION}" ]] || fail "hashcash solver returned empty solution"
echo "  solved: solution=${SOLUTION}"

# 4b-ii) Mint MFA token via the DEMO_MODE shortcut. This route is AUTH_ONLY
#        (bypasses trust + hashcash), so we send only the JWT.
MFA_RESP="$(mktemp)"
trap 'rm -f "${HEADERS_4A}" "${BODY_4A}" "${MFA_RESP}"' EXIT
MFA_CODE="$(curl -sS -o "${MFA_RESP}" -w '%{http_code}' \
  -X POST "${GATEWAY}/demo/mfa-token" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-device-id: ${DEVICE_ID}")"
echo "POST /demo/mfa-token → ${MFA_CODE}"
cat "${MFA_RESP}"; echo
[[ "${MFA_CODE}" == "201" || "${MFA_CODE}" == "200" ]] \
  || fail "expected 200/201 from /demo/mfa-token, got ${MFA_CODE}"
MFA_TOKEN="$(jq -r '.mfaToken // empty' "${MFA_RESP}")"
[[ -n "${MFA_TOKEN}" ]] || fail "/demo/mfa-token did not return mfaToken"

# 4b-iii) Replay the original request with PoW + MFA. Expect 200 + deterministic
#         orders body — i.e. proof the gateway promoted CHALLENGE → ALLOW.
FINAL_RESP="$(mktemp)"
trap 'rm -f "${HEADERS_4A}" "${BODY_4A}" "${MFA_RESP}" "${FINAL_RESP}"' EXIT
FINAL_CODE="$(curl -sS -o "${FINAL_RESP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${TRUST_OVERRIDE}" \
  -H "X-Hashcash-Nonce: ${NONCE}" \
  -H "X-Hashcash-Solution: ${SOLUTION}" \
  -H "X-MFA-Token: ${MFA_TOKEN}")"
echo "GET ${TARGET_PATH} (PoW + MFA) → ${FINAL_CODE}"
cat "${FINAL_RESP}"; echo
[[ "${FINAL_CODE}" == "200" ]] || fail "expected 200 after PoW+MFA promotion, got ${FINAL_CODE}"

ID="$(jq -r '.id // empty' "${FINAL_RESP}")"
[[ "${ID}" == "o-1" ]] || fail "expected id=o-1 in proxied body, got '${ID}'"

echo "scenario-4: OK (429 → solve PoW → mint MFA → 200)"
