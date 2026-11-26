#!/bin/bash
set -e

cd "$(dirname "$0")"

# 1. Crear CA interna
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=LabSeguridad/CN=Internal-Root-CA"

# 2. Certificado de Servidor (internal-admin-service)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=LabSeguridad/CN=internal-admin-service"

cat << 'EXT' > server.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = internal-admin-service
DNS.2 = localhost
IP.1 = 172.28.10.10
EXT

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server.ext

# 3. Certificado de Cliente (frontend-service)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=EC/ST=Pichincha/L=Quito/O=LabSeguridad/CN=frontend-service"

cat << 'EXT' > client.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EXT

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256 -extfile client.ext

rm -f *.csr *.ext *.srl
chmod 644 *.crt
chmod 600 *.key

echo "Certificados mTLS generados correctamente en hardening/certs/"
