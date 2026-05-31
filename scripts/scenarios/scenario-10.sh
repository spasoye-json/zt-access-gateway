#!/usr/bin/env bash
# Scenario 10 — fail-fast config validation for missing MFA env (HUMAN-UAT #33, criterion 3).
#
# The gateway must refuse to BOOT when a required MFA secret is absent, rather
# than starting and failing on the first MFA request. ConfigModule.forRoot()
# evaluates its Joi schema during NestFactory.create(), before runMigrations(),
# so this fails without needing a database.
#
# Boots dist/main.js from a clean working directory (so the repo .env is NOT
# auto-loaded) with every required var set inline EXCEPT MFA_JWT_SECRET, and
# asserts: non-zero exit + a "Config validation error" naming MFA_JWT_SECRET,
# and that the process never reached "listening".
#
# Exits non-zero on any mismatch.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

fail() { echo "scenario-10: $*" >&2; exit 1; }

# Need a compiled entrypoint. Build once if absent.
if [[ ! -f "${REPO_ROOT}/dist/main.js" ]]; then
  echo "scenario-10: dist/main.js not found — building…"
  ( cd "${REPO_ROOT}" && npm run build >/dev/null 2>&1 ) || fail "npm run build failed"
fi

# Minimal valid config for every REQUIRED var except MFA_JWT_SECRET.
export PROXY_SERVICE_REGISTRY='{"orders":"https://orders-service:8443"}'
export MTLS_CA_CERT_PATH=/dev/null
export MTLS_CLIENT_CERT_PATH=/dev/null
export MTLS_CLIENT_KEY_PATH=/dev/null
export MTLS_ALLOWED_SUBJECTS=cn=test
export JWT_SECRET='test-secret-that-is-at-least-32-chars-long!'
export DATABASE_URL='postgresql://localhost:5432/zt_test'
export HASHCASH_HMAC_SECRET="$(printf 'a%.0s' {1..64})"
export MFA_TOTP_ENCRYPTION_KEY="$(printf 'a%.0s' {1..32} | base64)"
unset MFA_JWT_SECRET

WORKDIR="$(mktemp -d)"
OUT="$(mktemp)"
trap 'rm -rf "${WORKDIR}" "${OUT}"' EXIT

# Run from an empty cwd so @nestjs/config does NOT pick up the repo's .env.
set +e
( cd "${WORKDIR}" && timeout 60 node "${REPO_ROOT}/dist/main.js" ) >"${OUT}" 2>&1
EXIT_CODE=$?
set -e

echo "boot exit code: ${EXIT_CODE}"
echo "----- boot output (tail) -----"
tail -5 "${OUT}"
echo "------------------------------"

[[ "${EXIT_CODE}" -ne 0 ]] || fail "expected non-zero exit, got 0 (gateway booted with a missing MFA secret)"
grep -q 'Config validation error' "${OUT}" || fail "expected a 'Config validation error' in boot output"
grep -q 'MFA_JWT_SECRET' "${OUT}" || fail "expected the error to name MFA_JWT_SECRET"
grep -qi 'listening' "${OUT}" && fail "gateway reported listening — it must not start with a missing MFA secret"

echo "scenario-10: OK (boot refused with missing MFA_JWT_SECRET; exit ${EXIT_CODE})"
