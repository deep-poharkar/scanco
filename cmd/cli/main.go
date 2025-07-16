package main

import (
	"github.com/spf13/cobra"
	"github.com/yourusername/scanco/pkg/admission"
)

func main() {
	// Add webhook command
	webhookCmd := &cobra.Command{
		Use:   "webhook",
		Short: "Run in webhook mode for Kubernetes admission control",
		Long: `Run as a webhook server for Kubernetes admission control.
Uses the same scanning and policy logic as CLI mode but exposes it via HTTPS.`,
		RunE: runWebhook,
	}

	// Simplified webhook flags
	webhookCmd.Flags().Int("port", 8443, "Port to listen on")
	webhookCmd.Flags().String("cert-file", "", "Path to TLS certificate file")
	webhookCmd.Flags().String("key-file", "", "Path to TLS key file")

	rootCmd.AddCommand(webhookCmd)
	// ... rest of main()
}

func runWebhook(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	certFile, _ := cmd.Flags().GetString("cert-file")
	keyFile, _ := cmd.Flags().GetString("key-file")

	opts := admission.WebhookOptions{
		Port:     port,
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	server := admission.NewWebhookServer(opts)
	return server.Run()
}
