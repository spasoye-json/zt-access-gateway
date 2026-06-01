#!/usr/bin/env bash
# Scenario 3 — honeypot deception + blacklist enforcement.
#
# Exercises the full deception layer end to end:
#   3a) GET /.env → 200 deceptive body (trap fires; JA4H blacklisted, terminal).
#   3b) The SAME client (identical request → identical JA4H) hits again →
#       403 Forbidden after a 2-5s tarpit (Ja4hMiddleware enforcement).
#   3c) An authenticated proxied request carries x-ja4h downstream: the demo
#       orders-service echoes it back as received_ja4h (64-hex SHA-256).
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
DECOY_PATH="${DECOY_PATH:-/.env}"
PROXY_PATH="${PROXY_PATH:-/orders/o-1}"
TARPIT_MIN_MS="${TARPIT_MIN_MS:-1500}"

fail() {
  echo "scenario-3: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

RESP="$(mktemp)"
trap 'rm -f "${RESP}"' EXIT

# 3a) Trip the trap. The decoy returns a deceptive 200 and blacklists the JA4H.
CODE_3A="$(curl -sS -o "${RESP}" -w '%{http_code}' "${GATEWAY}${DECOY_PATH}")"
echo "3a: GET ${DECOY_PATH} (1st) → ${CODE_3A}"
[[ "${CODE_3A}" == "200" ]] || fail "expected deceptive 200 on first decoy hit, got ${CODE_3A}"
if [[ "${DECOY_PATH}" == "/.env" ]]; then
  grep -q 'AKIAIOSFODNN7EXAMPLE' "${RESP}" || fail "decoy body missing the expected canary marker"
fi

# 3b) Identical request → identical JA4H → now blacklisted → 403 after a tarpit.
START_NS="$(date +%s%N)"
CODE_3B="$(curl -sS -o /dev/null -w '%{http_code}' "${GATEWAY}${DECOY_PATH}")"
END_NS="$(date +%s%N)"
LATENCY_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "3b: GET ${DECOY_PATH} (2nd, same fingerprint) → ${CODE_3B} in ${LATENCY_MS}ms"
[[ "${CODE_3B}" == "403" ]] || fail "expected 403 on blacklisted follow-up, got ${CODE_3B}"
(( LATENCY_MS >= TARPIT_MIN_MS )) \
  || fail "expected a visible tarpit (>= ${TARPIT_MIN_MS}ms), got ${LATENCY_MS}ms"

# 3c) x-ja4h propagation. An AUTHENTICATED request has a different header set
#     (Authorization present) → different JA4H → NOT blacklisted, so it proxies.
#     The orders-service echoes the forwarded fingerprint as received_ja4h.
#     Use an ADMIN token: BOPLA's /orders policy is admin:["*"], so the demo-only
#     received_ja4h field survives field-stripping. A 'user' token would have it
#     stripped to the production allowlist (id/status/total/amount/currency).
TOKEN="$(SUB=admin ROLES=admin node -r ts-node/register "${REPO_ROOT}/scripts/mint-demo-jwt.ts")" \
  || fail "failed to mint demo JWT"
[[ -n "${TOKEN}" ]] || fail "minted JWT is empty"

CODE_3C="$(curl -sS -o "${RESP}" -w '%{http_code}' \
  "${GATEWAY}${PROXY_PATH}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "x-demo-trust-score: 0.0")"
echo "3c: GET ${PROXY_PATH} (authenticated, trust 0.0) → ${CODE_3C}"
cat "${RESP}"; echo
[[ "${CODE_3C}" == "200" ]] || fail "expected 200 on proxied request, got ${CODE_3C}"
RECV_JA4H="$(jq -r '.received_ja4h // empty' "${RESP}")"
[[ "${RECV_JA4H}" =~ ^[0-9a-f]{64}$ ]] \
  || fail "expected received_ja4h to be a 64-hex JA4H forwarded downstream, got '${RECV_JA4H}'"

echo "scenario-3: OK (trap 200 → blacklist 403 in ${LATENCY_MS}ms → x-ja4h forwarded: ${RECV_JA4H:0:12}…)"
