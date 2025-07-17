package main

import (
	"fmt"
	"os"

	"scanco/pkg/admission"
	"scanco/pkg/admission/server"
	"scanco/pkg/admission/webhook"
	"scanco/pkg/policy"
	"scanco/pkg/scanner/container"
	"scanco/pkg/vulnerability"
	"scanco/pkg/vulnerability/nvd"

	"github.com/spf13/cobra"

	"github.com/sirupsen/logrus"
)

var rootCmd = &cobra.Command{
	Use:   "scanco",
	Short: "A container image security scanner",
	Long: `ScanCo is a security tool that scans container images for vulnerabilities
and enforces security policies both as a CLI tool and as a Kubernetes admission controller.`,
}

func main() {
	// Add webhook command
	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Run in webhook mode for Kubernetes admission control",
		Long: `Run as a webhook server for Kubernetes admission control.
Uses the same scanning and policy logic as CLI mode but exposes it via HTTPS.`,
		RunE: runWebhook,
	}

	// Add webhook flags
	webhookCmd.Flags().Int("port", 8443, "Port to listen on")
	webhookCmd.Flags().String("cert-file", "", "Path to TLS certificate file")
	webhookCmd.Flags().String("key-file", "", "Path to TLS key file")
	webhookCmd.Flags().String("policy", "", "Path to security policy file")
	webhookCmd.Flags().String("api-key", "", "NVD API key (optional)")

	rootCmd.AddCommand(webhookCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runWebhook(cmd *cobra.Command, args []string) error {
	// Get flags
	port, _ := cmd.Flags().GetInt("port")
	certFile, _ := cmd.Flags().GetString("cert-file")
	keyFile, _ := cmd.Flags().GetString("key-file")
	policyFile, _ := cmd.Flags().GetString("policy")
	apiKey, _ := cmd.Flags().GetString("api-key")

	// Validate required flags
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("TLS certificate and key files are required")
	}

	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Create NVD client
	nvdConfig := nvd.DefaultConfig()
	if apiKey != "" {
		nvdConfig.APIKey = apiKey
	}

	// Create scanners
	containerScanner := container.NewImageScanner()
	vulnScanner := vulnerability.NewScanner(
		nvd.NewClient(nvdConfig),
	)

	// Load security policies
	var policies []*policy.Policy
	if policyFile != "" {
		parser := policy.NewParser()
		p, err := parser.ParseFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to load policy file: %v", err)
		}
		policies = append(policies, p)
	}

	// Create policy evaluator
	evaluator := policy.NewEvaluator(policies)

	// Create webhook handler
	handler := webhook.NewHandler(containerScanner, vulnScanner, evaluator, logger)

	// Create and start webhook server
	config := &admission.Config{
		CertFile:   certFile,
		KeyFile:    keyFile,
		Port:       port,
		PolicyFile: policyFile,
	}

	srv := server.NewServer(config, handler, logger)
	logger.Infof("Starting admission webhook server on port %d", port)
	return srv.Start()
}
