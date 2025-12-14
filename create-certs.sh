#!/bin/bash
set -e

mkdir -p certs

echo "Creating Certificate Authority..."
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 365 \
  -key certs/ca.key \
  -out certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=zt-gateway-ca"

create_cert () {
  NAME=$1

  echo "Creating certificate for $NAME..."

  openssl genrsa -out certs/$NAME.key 2048

  cat > certs/$NAME.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $NAME
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

  openssl req -new \
    -key certs/$NAME.key \
    -out certs/$NAME.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$NAME"

  openssl x509 -req -days 365 \
    -in certs/$NAME.csr \
    -CA certs/ca.crt \
    -CAkey certs/ca.key \
    -CAcreateserial \
    -out certs/$NAME.crt \
    -extfile certs/$NAME.ext
}

create_cert gateway
create_cert users-service
create_cert orders-service
create_cert permissions-service

rm certs/*.csr certs/*.ext certs/*.srl

echo "Certificates generated successfully with SAN support."
