#!/bin/bash

# Create Certificate Authority (CA)
echo "Creating Certificate Authority..."

# Generate CA private key
openssl genrsa -out certs/ca.key 2048

# Generate CA certificate
openssl req -new -x509 -days 365 -key certs/ca.key -out certs/ca.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=zt-gateway-ca"

echo "Creating Gateway Certificate and Key..."

# Generate gateway private key
openssl genrsa -out certs/gateway.key 2048

# Create certificate signing request for gateway
openssl req -new -key certs/gateway.key -out certs/gateway.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=gateway"

# Sign the gateway certificate with CA
openssl x509 -req -days 365 -in certs/gateway.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/gateway.crt

echo "Creating Microservice Certificates and Keys..."

# Generate users service private key
openssl genrsa -out certs/users-service.key 2048
# Create CSR and sign for users service
openssl req -new -key certs/users-service.key -out certs/users-service.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=users-service"
openssl x509 -req -days 365 -in certs/users-service.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/users-service.crt

# Generate orders service private key
openssl genrsa -out certs/orders-service.key 2048
# Create CSR and sign for orders service
openssl req -new -key certs/orders-service.key -out certs/orders-service.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=orders-service"
openssl x509 -req -days 365 -in certs/orders-service.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/orders-service.crt

# Generate permissions service private key
openssl genrsa -out certs/permissions-service.key 2048
# Create CSR and sign for permissions service
openssl req -new -key certs/permissions-service.key -out certs/permissions-service.csr -subj "/C=US/ST=State/L=City/O=Organization/CN=permissions-service"
openssl x509 -req -days 365 -in certs/permissions-service.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/permissions-service.crt

# Cleanup CSR files
rm certs/*.csr
rm certs/ca.srl

echo "Certificates generated successfully!"
echo "CA: certs/ca.crt"
echo "Gateway: certs/gateway.crt, certs/gateway.key"
echo "Users Service: certs/users-service.crt, certs/users-service.key"
echo "Orders Service: certs/orders-service.crt, certs/orders-service.key"
echo "Permissions Service: certs/permissions-service.crt, certs/permissions-service.key"