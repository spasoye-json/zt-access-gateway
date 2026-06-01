#!/usr/bin/env bash
# Scenario 4 — high-risk request → hashcash PoW → MFA step-up (real TOTP).
#
# Drives the PRODUCTION step-up path. Under the demo thresholds
# (HASHCASH_TRIGGER=0.6, POLICY_CHALLENGE=0.7) a high-risk request hits hashcash
# BEFORE policy, so a genuine MFA challenge is only reached after solving the PoW.
# Asserts:
#   4a) trust 0.7, no PoW → 429 proof_of_work_required (+ X-Hashcash-Challenge).
#   4b) retry with a solved PoW but NO MFA token → 401 mfa_required (the gate).
#   4c) enroll → confirm → /mfa/initiate → /mfa/verify (real TOTP) → MFA token;
#       retry with a fresh PoW + x-mfa-token → 200 (CHALLENGE promoted to ALLOW).
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
HIGH_SCORE="${HIGH_SCORE:-0.7}"        # > hashcash trigger (0.6) AND >= challenge (0.7), < deny (0.9)
# deviceId MUST equal the JWT's deviceId claim — MfaPromotionStage validates the
# token against claims.deviceId, while /mfa/verify binds it from x-device-id.
DEVICE_ID="${DEVICE_ID:-alice-device-1}"

fail() { echo "scenario-4: $*" >&2; exit 1; }
mint() { SUB="$1" ROLES="$2" node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts"; }
totp() { node -r ts-node/register "${REPO_ROOT}/scripts/totp.ts" "$1"; }
solve_pow() { node -r ts-node/register "${REPO_ROOT}/scripts/hashcash-solve.ts" "$1" "$2"; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

TOKEN="$(mint alice user)" || fail "failed to mint alice JWT"
ADMIN="$(mint admin admin)" || fail "failed to mint admin JWT"
TMP="$(mktemp)"; HDRS="$(mktemp)"; trap 'rm -f "${TMP}" "${HDRS}"' EXIT

# request_pow_challenge → fires a high-risk request with no PoW, asserts 429,
# parses the X-Hashcash-Challenge header, and exports NONCE + SOLUTION.
# The wire format is "<nonce>:<difficulty>"; the base64url nonce alphabet
# excludes ':', so the last ':' is unambiguously the difficulty separator.
request_pow_challenge() {
  local code line val difficulty
  code="$(curl -sS -D "${HDRS}" -o "${TMP}" -w '%{http_code}' \
    "${GATEWAY}${TARGET_PATH}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "x-demo-trust-score: ${HIGH_SCORE}")"
  [[ "${code}" == "429" ]] || fail "expected 429 hashcash challenge, got ${code}"
  [[ "$(jq -r '.error // empty' "${TMP}")" == "proof_of_work_required" ]] \
    || fail "expected proof_of_work_required"
  line="$(grep -i '^x-hashcash-challenge:' "${HDRS}" | tr -d '\r' || true)"
  [[ -n "${line}" ]] || fail "missing X-Hashcash-Challenge header"
  val="${line#*: }"
  NONCE="${val%:*}"
  difficulty="${val##*:}"
  SOLUTION="$(solve_pow "${NONCE}" "${difficulty}")" || fail "hashcash solver failed"
  [[ -n "${SOLUTION}" ]] || fail "empty PoW solution"
}

# 4a) High-risk request without PoW → 429.
request_pow_challenge
echo "4a: GET ${TARGET_PATH} (trust ${HIGH_SCORE}, no PoW) → 429; solved PoW"

# 4b) Retry with PoW but no MFA token → 401 mfa_required (the challenge gate).
CODE_4B="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${HIGH_SCORE}" \
  -H "X-Hashcash-Nonce: ${NONCE}" \
  -H "X-Hashcash-Solution: ${SOLUTION}")"
echo "4b: retry (PoW, no MFA) → ${CODE_4B}"
[[ "${CODE_4B}" == "401" ]] || fail "expected 401 mfa_required after PoW without MFA, got ${CODE_4B}"
[[ "$(jq -r '.error // empty' "${TMP}")" == "mfa_required" ]] || fail "expected error=mfa_required on 4b"

# 4c) Real MFA: enroll → confirm → initiate → verify → token; retry with fresh PoW + token → 200.
curl -sS -o /dev/null -X DELETE "${GATEWAY}/mfa/admin/enrollment/alice" \
  -H "Authorization: Bearer ${ADMIN}" || true   # reset so re-runs don't 409
ENROLL_CODE="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}")"
[[ "${ENROLL_CODE}" == "201" ]] || fail "expected 201 from /mfa/enroll, got ${ENROLL_CODE}"
ENROLLMENT_ID="$(jq -r '.enrollmentId // empty' "${TMP}")"
SECRET="$(jq -r '.otpauthUri // empty' "${TMP}" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
[[ -n "${SECRET}" ]] || fail "could not extract base32 secret from otpauthUri"

CONFIRM_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll/confirm" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}" -H 'Content-Type: application/json' \
  -d "{\"enrollmentId\":\"${ENROLLMENT_ID}\",\"totpCode\":\"$(totp "${SECRET}")\"}")"
[[ "${CONFIRM_CODE}" == "200" ]] || fail "expected 200 from enroll/confirm, got ${CONFIRM_CODE}"

CHALLENGE_ID="$(curl -sS -X POST "${GATEWAY}/mfa/initiate" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}" | jq -r '.challengeId // empty')"
[[ -n "${CHALLENGE_ID}" ]] || fail "/mfa/initiate did not return challengeId"
VERIFY_CODE="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/verify" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}" -H 'Content-Type: application/json' \
  -d "{\"challengeId\":\"${CHALLENGE_ID}\",\"totpCode\":\"$(totp "${SECRET}")\"}")"
echo "4c: POST /mfa/verify → ${VERIFY_CODE}"
[[ "${VERIFY_CODE}" == "200" ]] || fail "expected 200 from /mfa/verify, got ${VERIFY_CODE}"
MFA_TOKEN="$(jq -r '.token // empty' "${TMP}")"
[[ -n "${MFA_TOKEN}" ]] || fail "/mfa/verify did not return a token"

request_pow_challenge   # fresh PoW (the 4b nonce was consumed)
PROMOTE_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${HIGH_SCORE}" \
  -H "X-Hashcash-Nonce: ${NONCE}" \
  -H "X-Hashcash-Solution: ${SOLUTION}" \
  -H "x-mfa-token: ${MFA_TOKEN}")"
echo "4c: retry (PoW + x-mfa-token) → ${PROMOTE_HTTP}"
[[ "${PROMOTE_HTTP}" == "200" ]] || fail "expected 200 after MFA promotion, got ${PROMOTE_HTTP}"
[[ "$(jq -r '.id // empty' "${TMP}")" == "o-1" ]] || fail "expected proxied orders body (id=o-1)"

echo "scenario-4: OK (429 PoW → 401 mfa_required → real TOTP verify → promote 200)"
