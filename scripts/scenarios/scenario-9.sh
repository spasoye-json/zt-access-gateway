#!/usr/bin/env bash
# Scenario 9 — MFA enrollment + admin-gated reset (HUMAN-UAT #34).
#
# Asserts:
#   9a) Admin reset of an enrollment: DELETE /mfa/admin/enrollment/:userId with
#       an admin JWT → 200 (idempotent; deleted true|false).
#   9b) Enroll → confirm (real TOTP) happy path commits an enrollment.
#   9c) The admin route is role-gated: the SAME delete with a non-admin JWT → 403.
#
# Encryption-at-rest (TOTP secret stored as AES-256-GCM ciphertext) is not
# observable over HTTP — it is verified by the integration test
# tests/integration/mfa-enrollment-encryption-at-rest.e2e-spec.ts.
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
USER_ID="${USER_ID:-alice}"
DEVICE_ID="${DEVICE_ID:-${USER_ID}-device-1}"

fail() { echo "scenario-9: $*" >&2; exit 1; }
mint() { SUB="$1" ROLES="$2" node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts"; }
totp() { node -r ts-node/register "${REPO_ROOT}/scripts/totp.ts" "$1"; }

command -v jq >/dev/null 2>&1 || fail "jq is required"

USER_TOKEN="$(mint "${USER_ID}" user)" || fail "failed to mint user JWT"
ADMIN_TOKEN="$(mint admin admin)" || fail "failed to mint admin JWT"
TMP="$(mktemp)"; trap 'rm -f "${TMP}"' EXIT

# 9a) Admin reset (also clears any prior enrollment so 9b is repeatable).
RESET_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' -X DELETE \
  "${GATEWAY}/mfa/admin/enrollment/${USER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")"
echo "DELETE /mfa/admin/enrollment/${USER_ID} (admin) → ${RESET_HTTP}"
cat "${TMP}"; echo
[[ "${RESET_HTTP}" == "200" ]] || fail "expected 200 from admin reset, got ${RESET_HTTP}"
jq -e 'has("deleted")' "${TMP}" >/dev/null 2>&1 || fail "admin reset body missing 'deleted' field"

# 9b) Enroll → confirm happy path.
ENROLL_HTTP="$(curl -sS -o "${TMP}" -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll" \
  -H "Authorization: Bearer ${USER_TOKEN}" -H "x-device-id: ${DEVICE_ID}")"
echo "POST /mfa/enroll → ${ENROLL_HTTP}"
[[ "${ENROLL_HTTP}" == "201" ]] || fail "expected 201 from /mfa/enroll, got ${ENROLL_HTTP}"
ENROLLMENT_ID="$(jq -r '.enrollmentId // empty' "${TMP}")"
OTPAUTH_URI="$(jq -r '.otpauthUri // empty' "${TMP}")"
SECRET="$(printf '%s' "${OTPAUTH_URI}" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p')"
[[ -n "${ENROLLMENT_ID}" && -n "${SECRET}" ]] || fail "enroll did not return enrollmentId + secret"

CONFIRM_HTTP="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${GATEWAY}/mfa/enroll/confirm" \
  -H "Authorization: Bearer ${USER_TOKEN}" -H "x-device-id: ${DEVICE_ID}" \
  -H 'Content-Type: application/json' \
  -d "{\"enrollmentId\":\"${ENROLLMENT_ID}\",\"totpCode\":\"$(totp "${SECRET}")\"}")"
echo "POST /mfa/enroll/confirm → ${CONFIRM_HTTP}"
[[ "${CONFIRM_HTTP}" == "200" ]] || fail "expected 200 from enroll/confirm, got ${CONFIRM_HTTP}"

# 9c) The admin route rejects a non-admin caller (RolesGuard → 403).
FORBIDDEN_HTTP="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
  "${GATEWAY}/mfa/admin/enrollment/${USER_ID}" \
  -H "Authorization: Bearer ${USER_TOKEN}")"
echo "DELETE /mfa/admin/enrollment/${USER_ID} (non-admin) → ${FORBIDDEN_HTTP}"
[[ "${FORBIDDEN_HTTP}" == "403" ]] || fail "expected 403 for non-admin reset, got ${FORBIDDEN_HTTP}"

echo "scenario-9: OK (admin reset 200 → enroll/confirm 200 → non-admin reset 403)"
