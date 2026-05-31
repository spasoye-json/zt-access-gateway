#!/usr/bin/env bash
# Scenario 8 — real /mfa/initiate → /mfa/verify promotion + rate limit (HUMAN-UAT #33).
#
# Drives the PRODUCTION MFA endpoints with a real TOTP code (unlike scenario-4,
# which uses the /demo/mfa-token shortcut). Under the demo thresholds
# (HASHCASH_TRIGGER=0.6, POLICY_CHALLENGE=0.7) a high-risk request hits hashcash
# BEFORE policy, so a genuine MFA challenge is only reached after solving the PoW.
# Asserts:
#   8a) trust 0.7, no PoW → 429 proof_of_work_required (+ X-Hashcash-Challenge).
#   8b) retry with a solved PoW but NO MFA token → 401 mfa_required (the gate).
#   8c) enroll → confirm → /mfa/initiate → /mfa/verify (real TOTP) → MFA token;
#       retry with a fresh PoW + x-mfa-token → 200 (CHALLENGE promoted to ALLOW).
#   8d) Exceeding MFA_RATE_LIMIT_MAX /mfa/initiate calls → 429 + Retry-After
#       (fresh user so the per-user window count is deterministic).
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
TARGET_PATH="${TARGET_PATH:-/orders/o-1}"
HIGH_SCORE="${HIGH_SCORE:-0.7}"        # > hashcash trigger (0.6) AND >= challenge (0.7), < deny (0.9)
RATE_MAX="${MFA_RATE_LIMIT_MAX:-5}"
# deviceId MUST equal the JWT's deviceId claim — MfaPromotionStage validates the
# token against claims.deviceId, while /mfa/verify binds it from x-device-id.
DEVICE_ID="${DEVICE_ID:-alice-device-1}"

fail() { echo "scenario-8: $*" >&2; exit 1; }
mint() { SUB="$1" ROLES="$2" node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts"; }
totp() { node -r ts-node/register "${REPO_ROOT}/scripts/totp.ts" "$1"; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

TOKEN="$(mint alice user)" || fail "failed to mint alice JWT"
ADMIN="$(mint admin admin)" || fail "failed to mint admin JWT"
TMP="$(mktemp)"; HDRS="$(mktemp)"; trap 'rm -f "${TMP}" "${HDRS}"' EXIT

# solve_pow <nonce> <difficulty> → prints solution
solve_pow() { node -r ts-node/register "${REPO_ROOT}/scripts/hashcash-solve.ts" "$1" "$2"; }

# request_pow_challenge → fires a high-risk request with no PoW, asserts 429,
# parses the X-Hashcash-Challenge header, and exports NONCE + SOLUTION.
request_pow_challenge() {
  local code
  code="$(curl -sS -D "${HDRS}" -o "${TMP}" -w '%{http_code}' \
    "${GATEWAY}${TARGET_PATH}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "x-demo-trust-score: ${HIGH_SCORE}")"
  [[ "${code}" == "429" ]] || fail "expected 429 hashcash challenge, got ${code}"
  [[ "$(jq -r '.error // empty' "${TMP}")" == "proof_of_work_required" ]] \
    || fail "expected proof_of_work_required"
  local line val
  line="$(grep -i '^x-hashcash-challenge:' "${HDRS}" | tr -d '\r' || true)"
  [[ -n "${line}" ]] || fail "missing X-Hashcash-Challenge header"
  val="${line#*: }"
  NONCE="${val%:*}"
  local difficulty="${val##*:}"
  SOLUTION="$(solve_pow "${NONCE}" "${difficulty}")" || fail "hashcash solver failed"
  [[ -n "${SOLUTION}" ]] || fail "empty PoW solution"
}

# 8a) High-risk request without PoW → 429.
request_pow_challenge
echo "8a: GET ${TARGET_PATH} (trust ${HIGH_SCORE}, no PoW) → 429; solved PoW"

# 8b) Retry with PoW but no MFA token → 401 mfa_required (the challenge gate).
CODE_8B="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${HIGH_SCORE}" \
  -H "X-Hashcash-Nonce: ${NONCE}" \
  -H "X-Hashcash-Solution: ${SOLUTION}")"
echo "8b: retry (PoW, no MFA) → ${CODE_8B}"
[[ "${CODE_8B}" == "401" ]] || fail "expected 401 mfa_required after PoW without MFA, got ${CODE_8B}"
[[ "$(jq -r '.error // empty' "${TMP}")" == "mfa_required" ]] || fail "expected error=mfa_required on 8b"

# 8c) Real MFA: enroll → confirm → initiate → verify → token; retry with fresh PoW + token → 200.
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
echo "8c: POST /mfa/verify → ${VERIFY_CODE}"
[[ "${VERIFY_CODE}" == "200" ]] || fail "expected 200 from /mfa/verify, got ${VERIFY_CODE}"
MFA_TOKEN="$(jq -r '.token // empty' "${TMP}")"
[[ -n "${MFA_TOKEN}" ]] || fail "/mfa/verify did not return a token"

request_pow_challenge   # fresh PoW (the 8b nonce was consumed)
PROMOTE_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${HIGH_SCORE}" \
  -H "X-Hashcash-Nonce: ${NONCE}" \
  -H "X-Hashcash-Solution: ${SOLUTION}" \
  -H "x-mfa-token: ${MFA_TOKEN}")"
echo "8c: retry (PoW + x-mfa-token) → ${PROMOTE_HTTP}"
[[ "${PROMOTE_HTTP}" == "200" ]] || fail "expected 200 after MFA promotion, got ${PROMOTE_HTTP}"
[[ "$(jq -r '.id // empty' "${TMP}")" == "o-1" ]] || fail "expected proxied orders body (id=o-1)"

# 8d) Rate limit — fresh user so the per-user window count is deterministic.
RL_USER="rl-$$-${RANDOM}"
RL_TOKEN="$(mint "${RL_USER}" user)" || fail "failed to mint rate-limit user JWT"
RL_LAST=""
for i in $(seq 1 $((RATE_MAX + 1))); do
  RL_LAST="$(curl -sS -o /dev/null -D "${HDRS}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/initiate" \
    -H "Authorization: Bearer ${RL_TOKEN}" -H "x-device-id: ${RL_USER}-dev")"
  echo "  /mfa/initiate ${i}/$((RATE_MAX + 1)) → ${RL_LAST}"
done
[[ "${RL_LAST}" == "429" ]] || fail "expected attempt $((RATE_MAX + 1)) → 429, got ${RL_LAST}"
RETRY_AFTER="$(grep -i '^retry-after:' "${HDRS}" | tr -d '\r' | awk '{print $2}')"
[[ -n "${RETRY_AFTER}" ]] || fail "expected a Retry-After header on the 429"

echo "scenario-8: OK (429 PoW → 401 mfa_required → real verify → promote 200; rate limit 429 + Retry-After: ${RETRY_AFTER})"
