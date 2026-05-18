#!/usr/bin/env bash
# Scenario 2 — auth failure (PRD #1 user story 20, issue #9).
#
# Self-contained: fires GET /orders/o-1 twice — once with no Authorization
# header at all, and once with a syntactically valid but signature-bad JWT.
# Both must return 401. Exits non-zero on any unexpected status.

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
  echo "scenario-2: $*" >&2
  exit 1
}

# 1) No Authorization header → 401.
NO_AUTH_RESP="$(mktemp)"
trap 'rm -f "${NO_AUTH_RESP}"' EXIT
NO_AUTH_CODE="$(curl -sS -o "${NO_AUTH_RESP}" -w '%{http_code}' "${GATEWAY}${TARGET_PATH}")"
echo "GET ${TARGET_PATH} (no Authorization) → ${NO_AUTH_CODE}"
cat "${NO_AUTH_RESP}"; echo
[[ "${NO_AUTH_CODE}" == "401" ]] || fail "expected 401 without Authorization, got ${NO_AUTH_CODE}"

# 2) Bad JWT (well-formed shape, wrong signature) → 401.
# Minted at runtime with a deliberately wrong HS256 secret so no JWT-shaped
# literal lives in the source (avoids tripping JWT secret-detectors like
# GitGuardian on a token that is by-design unverifiable).
BAD_TOKEN="$(JWT_SECRET='this-secret-is-not-the-real-one-32chars-pad!' SUB=alice ROLES=user \
  node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint wrong-secret JWT"
[[ -n "${BAD_TOKEN}" ]] || fail "minted bad JWT is empty"
BAD_RESP="$(mktemp)"
trap 'rm -f "${NO_AUTH_RESP}" "${BAD_RESP}"' EXIT
BAD_CODE="$(curl -sS -o "${BAD_RESP}" -w '%{http_code}' \
  "${GATEWAY}${TARGET_PATH}" \
  -H "Authorization: Bearer ${BAD_TOKEN}")"
echo "GET ${TARGET_PATH} (bad signature) → ${BAD_CODE}"
cat "${BAD_RESP}"; echo
[[ "${BAD_CODE}" == "401" ]] || fail "expected 401 with bad JWT, got ${BAD_CODE}"

echo "scenario-2: OK"
