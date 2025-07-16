#!/bin/bash
set -e

# Default values
NAMESPACE="scanco-system"
SERVICE_NAME="scanco-webhook-svc"
SECRET_NAME="webhook-certs"

# Create output directory
CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

# Generate CA key and certificate
openssl genrsa -out "${CERT_DIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" -sha256 -days 365 -out "${CERT_DIR}/ca.crt" \
    -subj "/O=scanco/CN=admission-controller-ca"

# Generate server key
openssl genrsa -out "${CERT_DIR}/server.key" 2048

# Generate server CSR
cat > "${CERT_DIR}/csr.conf" <<EOF
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
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
EOF

openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
    -subj "/O=scanco/CN=${SERVICE_NAME}.${NAMESPACE}.svc" \
    -config "${CERT_DIR}/csr.conf"

# Sign the server certificate
openssl x509 -req -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -days 365 \
    -extensions v3_req \
    -extfile "${CERT_DIR}/csr.conf"

# Clean up CSR config and files
rm "${CERT_DIR}/csr.conf" "${CERT_DIR}/server.csr" "${CERT_DIR}/ca.key" "${CERT_DIR}/ca.srl"

echo "Certificates generated successfully in ${CERT_DIR}/"
echo "Use these files to create the Kubernetes secret:"
echo "kubectl create secret generic ${SECRET_NAME} \\"
echo "    --namespace ${NAMESPACE} \\"
echo "    --from-file=server.crt=${CERT_DIR}/server.crt \\"
echo "    --from-file=server.key=${CERT_DIR}/server.key" 