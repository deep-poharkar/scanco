#!/bin/bash

# Generate CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/O=scanco/CN=admission-ca"

# Generate server key
openssl genrsa -out server.key 2048

# Generate server CSR
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
DNS.4 = scanco-webhook-svc.default.svc.cluster.local
EOF

openssl req -new -key server.key -out server.csr -subj "/O=scanco/CN=scanco-webhook-svc.default.svc" -config server.conf

# Sign server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.conf

# Clean up
rm server.conf server.csr ca.srl

echo "Certificates generated successfully!" 