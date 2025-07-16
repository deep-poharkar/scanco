#!/bin/bash
set -e

# Build the admission controller image
echo "Building admission controller image..."
docker build -t scanco-webhook:latest .

# Create the webhook certificates secret
echo "Creating webhook certificates secret..."
kubectl create secret generic webhook-certs \
    --from-file=server.crt=test/certs/server.crt \
    --from-file=server.key=test/certs/server.key \
    --dry-run=client -o yaml | kubectl apply -f -

# Create the webhook config ConfigMap
echo "Creating webhook config ConfigMap..."
kubectl create configmap webhook-config \
    --from-file=policy.yaml=test/k8s/policy.yaml \
    --dry-run=client -o yaml | kubectl apply -f -

# Deploy the webhook
echo "Deploying webhook..."
kubectl apply -f test/k8s/deployment.yaml

# Wait for deployment to be ready
echo "Waiting for webhook deployment to be ready..."
kubectl rollout status deployment/scanco-webhook

# Create the ValidatingWebhookConfiguration
echo "Creating ValidatingWebhookConfiguration..."
CA_BUNDLE=$(base64 < test/certs/ca.crt | tr -d '\n')
sed "s/\${CA_BUNDLE}/${CA_BUNDLE}/" test/k8s/webhook.yaml | kubectl apply -f -

echo "Setup complete! Testing the webhook..."

# Create a test pod that should be allowed
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-allowed
spec:
  containers:
  - name: alpine
    image: alpine:latest
EOF

# Create a test pod that should be blocked (old version with known vulnerabilities)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-blocked
spec:
  containers:
  - name: alpine
    image: alpine:3.14
EOF

echo "Done! Check the results with: kubectl get pods" 