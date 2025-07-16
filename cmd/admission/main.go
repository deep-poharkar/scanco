package main

import (
	"flag"
	"log"
	"scanco/pkg/admission"
	"scanco/pkg/admission/server"
	"scanco/pkg/admission/webhook"
	"scanco/pkg/policy"
	"scanco/pkg/scanner/container"
	"scanco/pkg/vulnerability"
	"scanco/pkg/vulnerability/nvd"

	"github.com/sirupsen/logrus"
)

func main() {
	// Parse command line flags
	certFile := flag.String("cert", "", "Path to TLS certificate file")
	keyFile := flag.String("key", "", "Path to TLS key file")
	port := flag.Int("port", 8443, "Webhook server port")
	policyFile := flag.String("policy", "", "Path to security policy file")
	apiKey := flag.String("api-key", "", "NVD API key (optional)")
	flag.Parse()

	// Validate required flags
	if *certFile == "" || *keyFile == "" {
		log.Fatal("TLS certificate and key files are required")
	}

	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Create NVD client
	nvdConfig := nvd.DefaultConfig()
	if *apiKey != "" {
		nvdConfig.APIKey = *apiKey
	}

	// Create scanners
	containerScanner := container.NewImageScanner()
	vulnScanner := vulnerability.NewScanner(
		nvd.NewClient(nvdConfig),
	)

	// Load security policies
	var policies []*policy.Policy
	if *policyFile != "" {
		parser := policy.NewParser()
		p, err := parser.ParseFile(*policyFile)
		if err != nil {
			log.Fatalf("Failed to load policy file: %v", err)
		}
		policies = append(policies, p)
	}

	// Create policy evaluator
	evaluator := policy.NewEvaluator(policies)

	// Create webhook handler
	handler := webhook.NewHandler(containerScanner, vulnScanner, evaluator, logger)

	// Create and start webhook server
	config := &admission.Config{
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		Port:       *port,
		PolicyFile: *policyFile,
	}

	srv := server.NewServer(config, handler, logger)
	logger.Infof("Starting admission webhook server on port %d", *port)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
