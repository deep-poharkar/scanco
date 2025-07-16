# ScanCo - Container Security Scanner with Kubernetes Integration

ScanCo is an open-source container security scanner that can be used both as a CLI tool
and as a Kubernetes admission controller.

1. **Direct Scanner Mode**: Use the CLI to instantly scan container images for vulnerabilities and policy violations. Perfect for developers checking images during development or in CI/CD pipelines.

2. **Kubernetes Integration Mode**: Run ScanCo as a webhook that Kubernetes can call to scan images before they're deployed. Simply run `scanco webhook` and configure Kubernetes to use it - the same scanning engine will automatically check all containers before they're allowed to run in your cluster.

The tool implements a robust policy engine that lets you define security rules like maximum allowed vulnerability severity, blocked CVEs, allowed base images, and minimum CVSS scores. Whether you're scanning locally or integrating with Kubernetes, you get the same powerful security checks.

## Features

- Container image vulnerability scanning
- Policy-based image validation
- Kubernetes admission controller integration
- Customizable security policies
- Support for multiple registries

## CLI Usage

### Quick Start

1. **Clone and Build**

```bash
git clone https://github.com/yourusername/scanco.git
cd scanco
go build -o scanco cmd/cli/main.go
```

2. **Basic Commands**

```bash
# Scan a single image
./scanco scan alpine:3.14

# Scan with detailed output
./scanco scan --verbose nginx:latest

# Scan multiple images
./scanco scan alpine:3.14 ubuntu:22.04 nginx:latest

# Use custom policy file
./scanco scan --policy-file my-policy.yaml alpine:3.14

# Scan with different output format
./scanco scan --output json alpine:3.14
./scanco scan --output yaml alpine:3.14

# Show image details without scanning
./scanco inspect alpine:3.14

# List all available commands
./scanco --help
```

3. **Available Flags**

```bash
Global Flags:
  --verbose               Enable verbose output
  --output string        Output format (text, json, yaml) (default "text")
  --no-color             Disable color output

Scan Flags:
  --policy-file string   Custom policy file path
  --fail-on string      Exit with error on (high, medium, low) severity
  --registry string     Use specific registry
  --insecure           Allow insecure registries
  --timeout duration   Scan timeout (default 5m)
```

### Optional: Enhanced Features with API Keys

For advanced vulnerability scanning, you can configure API keys:

1. Create a `.env` file in the root directory:

```bash
# Optional: API keys for additional vulnerability databases
NVDB_API_KEY=your_api_key_here
VULNDB_API_KEY=your_api_key_here

# Optional: Registry credentials for private registries
DOCKER_USERNAME=your_username
DOCKER_PASSWORD=your_password
```

2. Additional commands with API keys:

```bash
# Detailed vulnerability scan with CVSS scores
./scanco scan --detailed alpine:3.14

# Generate compliance report
./scanco report --format pdf alpine:3.14

# Scan private registry images
./scanco scan --registry my-registry.com/my-image:latest
```

## Usage

### CLI Mode

```bash
# Basic scan
./scanco scan nginx:latest

# Scan with custom policy
./scanco scan --policy-file policy.yaml alpine:3.14

# Multiple image scan
./scanco scan nginx:latest alpine:3.14 ubuntu:22.04

# Scan with detailed output
./scanco scan --verbose nginx:latest
```

### Webhook Mode (for Kubernetes)

```bash
# Run as webhook server
./scanco webhook --port 8443 --cert-file cert.pem --key-file key.pem
```

The webhook mode runs an HTTPS server that implements the Kubernetes admission webhook interface. It uses the same scanning and policy logic as the CLI mode but serves it via HTTPS for Kubernetes integration.

Webhook flags:

```bash
--port int         Port to listen on (default 8443)
--cert-file path  Path to TLS certificate file (required)
--key-file path   Path to TLS key file (required)
```

## Kubernetes Integration

The admission controller automatically scans container images in:

- Pod creations
- Deployment creations
- StatefulSet creations
- DaemonSet creations
- Job creations
- CronJob creations

Example of a blocked deployment:

```bash
$ kubectl create deployment nginx --image=nginx:1.14
Error: admission webhook "scanco.security.io" denied the request:
Image validation failed:
- Image nginx:1.14 failed policy check:
  - severity: Vulnerability severity HIGH exceeds maximum allowed MEDIUM
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security issues, please email security@yourdomain.com or submit a security advisory on GitHub.

## License

MIT License - see [LICENSE](LICENSE) for details
