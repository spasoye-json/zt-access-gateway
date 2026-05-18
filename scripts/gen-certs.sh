#!/usr/bin/env bash
# Generate self-signed PKI for the demo stack.
# Idempotent: existing files are kept unless --force is passed.
#
# Output layout (relative to repo root, or $CERT_DIR if set):
#   certs/
#     ca.key            CA private key
#     ca.crt            CA self-signed root
#     gateway.key       gateway client private key
#     gateway.crt       gateway client cert (CN=gateway, signed by CA)
#     <service>.key     server private key
#     <service>.crt     server cert (CN=<service> + SANs, signed by CA)
#
# Services produced: passed as positional args (default: orders-service users-service).

set -euo pipefail

FORCE=0
SERVICES=()
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) SERVICES+=("$arg") ;;
  esac
done
if [ "${#SERVICES[@]}" -eq 0 ]; then
  SERVICES=("orders-service" "users-service")
fi

CERT_DIR="${CERT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/certs}"
mkdir -p "$CERT_DIR"

DAYS=825   # max accepted by modern browsers; comfortably past thesis defense
KEY_BITS=2048

regen() {
  # regen <file> — true if FORCE=1 or file missing
  [ "$FORCE" -eq 1 ] && return 0
  [ ! -f "$1" ] && return 0
  return 1
}

# ---------- CA ----------
if regen "$CERT_DIR/ca.key" || regen "$CERT_DIR/ca.crt"; then
  echo "[gen-certs] CA"
  openssl genrsa -out "$CERT_DIR/ca.key" "$KEY_BITS" 2>/dev/null
  openssl req -x509 -new -nodes -sha256 -days "$DAYS" \
    -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/CN=zt-gateway-demo-ca"
else
  echo "[gen-certs] CA exists, skipping"
fi

# ---------- helper: issue a leaf cert ----------
issue_cert() {
  local name="$1"       # filename stem
  local cn="$2"         # subject CN
  local san="$3"        # OpenSSL extensions block (subjectAltName=...) or empty

  local key="$CERT_DIR/${name}.key"
  local crt="$CERT_DIR/${name}.crt"
  local csr="$CERT_DIR/${name}.csr"
  local ext="$CERT_DIR/${name}.ext"

  if ! regen "$key" && ! regen "$crt"; then
    echo "[gen-certs] $name exists, skipping"
    return
  fi

  echo "[gen-certs] $name (CN=$cn)"
  openssl genrsa -out "$key" "$KEY_BITS" 2>/dev/null
  openssl req -new -key "$key" -out "$csr" -subj "/CN=$cn"

  {
    echo "basicConstraints = CA:FALSE"
    echo "keyUsage = digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = serverAuth, clientAuth"
    if [ -n "$san" ]; then echo "$san"; fi
  } > "$ext"

  openssl x509 -req -in "$csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$crt" -days "$DAYS" -sha256 \
    -extfile "$ext"

  rm -f "$csr" "$ext"
}

# ---------- gateway client cert ----------
issue_cert "gateway" "gateway" ""

# ---------- server certs ----------
for svc in "${SERVICES[@]}"; do
  san="subjectAltName = DNS:${svc}, DNS:localhost, IP:127.0.0.1"
  issue_cert "$svc" "$svc" "$san"
done

# Demo certs only — keep keys world-readable so the non-root container UID
# inside docker-compose can mount and read them. certs/ is gitignored anyway.
chmod 644 "$CERT_DIR"/*.key 2>/dev/null || true

echo "[gen-certs] done → $CERT_DIR"
