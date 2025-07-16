#!/bin/bash
set -e

# Generate CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/O=scanco/CN=admission-ca" -out ca.crt

# Generate server key and certificate signing request
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/O=scanco/CN=scanco-webhook-svc.default.svc" -out server.csr

# Create certificate config
cat > server.conf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = scanco-webhook-svc
DNS.2 = scanco-webhook-svc.default
DNS.3 = scanco-webhook-svc.default.svc
EOF

# Sign the server certificate
openssl x509 -req -days 365 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -extfile server.conf -extensions v3_req \
    -out server.crt

# Clean up temporary files
rm server.conf server.csr ca.srl

echo "Certificates generated successfully!" 