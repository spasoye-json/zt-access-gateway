#!/usr/bin/env bash
# Scenario 8 — real /mfa/initiate → /mfa/verify promotion + rate limit (HUMAN-UAT #33).
#
# Unlike scenario-4 (which mints via the /demo/mfa-token shortcut), this drives
# the PRODUCTION MFA endpoints with a real TOTP code. Asserts:
#   8a) A CHALLENGE-band request (trust 0.6 → above challenge, below hashcash)
#       with no MFA token → 401 mfa_required.
#   8b) enroll → confirm (real TOTP) so a committed secret exists.
#   8c) /mfa/initiate → /mfa/verify (real TOTP) → MFA token; retry the original
#       request with x-mfa-token → 200 (CHALLENGE promoted to ALLOW).
#   8d) Exceeding MFA_RATE_LIMIT_MAX /mfa/initiate calls in the window → 429 +
#       Retry-After (uses a fresh user so the count is deterministic).
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
CHALLENGE_SCORE="${CHALLENGE_SCORE:-0.6}"      # > challenge (0.5), < hashcash (0.7), < deny (0.8)
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
TMP="$(mktemp)"; trap 'rm -f "${TMP}"' EXIT

# 8a) CHALLENGE-band request without an MFA token → 401 mfa_required.
CODE_8A="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${CHALLENGE_SCORE}")"
echo "GET ${TARGET_PATH} (trust ${CHALLENGE_SCORE}, no MFA) → ${CODE_8A}"
[[ "${CODE_8A}" == "401" ]] || fail "expected 401 challenge, got ${CODE_8A}"
[[ "$(jq -r '.error // empty' "${TMP}")" == "mfa_required" ]] \
  || fail "expected body.error=mfa_required on 8a"

# 8b) Enroll a fresh secret. Reset first (admin) so re-runs don't hit 409.
curl -sS -o /dev/null -X DELETE "${GATEWAY}/mfa/admin/enrollment/alice" \
  -H "Authorization: Bearer ${ADMIN}" || true
ENROLL_CODE="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}")"
[[ "${ENROLL_CODE}" == "201" ]] || fail "expected 201 from /mfa/enroll, got ${ENROLL_CODE}"
ENROLLMENT_ID="$(jq -r '.enrollmentId // empty' "${TMP}")"
OTPAUTH_URI="$(jq -r '.otpauthUri // empty' "${TMP}")"
SECRET="$(printf '%s' "${OTPAUTH_URI}" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
[[ -n "${SECRET}" ]] || fail "could not extract base32 secret from otpauthUri"

CONFIRM_CODE_VAL="$(totp "${SECRET}")"
CONFIRM_HTTP="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll/confirm" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}" \
  -H 'Content-Type: application/json' \
  -d "{\"enrollmentId\":\"${ENROLLMENT_ID}\",\"totpCode\":\"${CONFIRM_CODE_VAL}\"}")"
echo "POST /mfa/enroll/confirm → ${CONFIRM_HTTP}"
[[ "${CONFIRM_HTTP}" == "200" ]] || fail "expected 200 from enroll/confirm, got ${CONFIRM_HTTP}"

# Wait for the next TOTP window so verify uses a code distinct from confirm's
# (guards against any server-side single-use replay protection).
VERIFY_CODE_VAL="${CONFIRM_CODE_VAL}"
for _ in $(seq 1 31); do
  VERIFY_CODE_VAL="$(totp "${SECRET}")"
  [[ "${VERIFY_CODE_VAL}" != "${CONFIRM_CODE_VAL}" ]] && break
  sleep 1
done

# 8c) initiate → verify → token → retry → 200.
INIT_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/initiate" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}")"
[[ "${INIT_HTTP}" == "201" ]] || fail "expected 201 from /mfa/initiate, got ${INIT_HTTP}"
CHALLENGE_ID="$(jq -r '.challengeId // empty' "${TMP}")"
[[ -n "${CHALLENGE_ID}" ]] || fail "/mfa/initiate did not return challengeId"

VERIFY_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/verify" \
  -H "Authorization: Bearer ${TOKEN}" -H "x-device-id: ${DEVICE_ID}" \
  -H 'Content-Type: application/json' \
  -d "{\"challengeId\":\"${CHALLENGE_ID}\",\"totpCode\":\"${VERIFY_CODE_VAL}\"}")"
echo "POST /mfa/verify → ${VERIFY_HTTP}"
[[ "${VERIFY_HTTP}" == "200" ]] || fail "expected 200 from /mfa/verify, got ${VERIFY_HTTP}"
MFA_TOKEN="$(jq -r '.token // empty' "${TMP}")"
[[ -n "${MFA_TOKEN}" ]] || fail "/mfa/verify did not return a token"

PROMOTE_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: ${CHALLENGE_SCORE}" \
  -H "x-mfa-token: ${MFA_TOKEN}")"
echo "GET ${TARGET_PATH} (trust ${CHALLENGE_SCORE}, x-mfa-token) → ${PROMOTE_HTTP}"
[[ "${PROMOTE_HTTP}" == "200" ]] || fail "expected 200 after MFA promotion, got ${PROMOTE_HTTP}"
[[ "$(jq -r '.id // empty' "${TMP}")" == "o-1" ]] || fail "expected proxied orders body (id=o-1)"

# 8d) Rate limit. Use a fresh user so the per-user window count is deterministic.
RL_USER="rl-$$-${RANDOM}"
RL_TOKEN="$(mint "${RL_USER}" user)" || fail "failed to mint rate-limit user JWT"
RL_LAST_HTTP=""
RL_HDRS="$(mktemp)"; trap 'rm -f "${TMP}" "${RL_HDRS}"' EXIT
for i in $(seq 1 $((RATE_MAX + 1))); do
  RL_LAST_HTTP="$(curl -sS -o /dev/null -D "${RL_HDRS}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/initiate" \
    -H "Authorization: Bearer ${RL_TOKEN}" -H "x-device-id: ${RL_USER}-device-1")"
  echo "  /mfa/initiate attempt ${i}/$((RATE_MAX + 1)) → ${RL_LAST_HTTP}"
done
[[ "${RL_LAST_HTTP}" == "429" ]] || fail "expected attempt $((RATE_MAX + 1)) to be 429, got ${RL_LAST_HTTP}"
RETRY_AFTER="$(grep -i '^retry-after:' "${RL_HDRS}" | tr -d '\r' | awk '{print $2}')"
[[ -n "${RETRY_AFTER}" ]] || fail "expected a Retry-After header on the 429"

echo "scenario-8: OK (challenge 401 → initiate/verify → promote 200; rate limit 429 + Retry-After: ${RETRY_AFTER})"
