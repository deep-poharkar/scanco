package policy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Parser handles loading and parsing of security policies
type Parser struct {
	// default policy to use if none specified
	defaultPolicy *Policy
}

// NewParser creates a new policy parser
func NewParser() *Parser {
	return &Parser{}
}

// SetDefaultPolicy sets the default policy
func (p *Parser) SetDefaultPolicy(policy *Policy) {
	p.defaultPolicy = policy
}

// ParseFile loads and parses a policy from a file
func (p *Parser) ParseFile(path string) (*Policy, error) {
	// Read file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening policy file: %w", err)
	}
	defer file.Close()

	return p.Parse(file)
}

// ParseFiles loads and parses multiple policy files from a directory
func (p *Parser) ParseFiles(dir string) ([]*Policy, error) {
	// Read all .yaml and .yml files in directory
	matches, err := filepath.Glob(filepath.Join(dir, "*.{yaml,yml}"))
	if err != nil {
		return nil, fmt.Errorf("finding policy files: %w", err)
	}

	var policies []*Policy
	for _, path := range matches {
		policy, err := p.ParseFile(path)
		if err != nil {
			return nil, fmt.Errorf("parsing policy file %s: %w", path, err)
		}
		policies = append(policies, policy)
	}

	if len(policies) == 0 && p.defaultPolicy != nil {
		// Use default policy if no policies found
		policies = append(policies, p.defaultPolicy)
	}

	return policies, nil
}

// Parse loads and parses a policy from a reader
func (p *Parser) Parse(r io.Reader) (*Policy, error) {
	var policy Policy

	// Parse YAML
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	// Validate policy
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}

	return &policy, nil
}

// DefaultPolicy returns a default security policy
func DefaultPolicy() *Policy {
	minCVSS := 7.0 // Block CVSS scores >= 7.0
	return &Policy{
		Name: "default-policy",
		Metadata: struct {
			Description string `yaml:"description"`
			Author      string `yaml:"author,omitempty"`
			Version     string `yaml:"version,omitempty"`
		}{
			Description: "Default security policy",
			Author:      "scanco",
			Version:     "1.0",
		},
		Rules: struct {
			MaxSeverity       Severity `yaml:"max_severity"`
			BlockedCVEs       []string `yaml:"blocked_cves,omitempty"`
			AllowedBaseImages []string `yaml:"allowed_base_images,omitempty"`
			MinCVSS           *float64 `yaml:"min_cvss,omitempty"`
		}{
			MaxSeverity: SeverityHigh,
			MinCVSS:     &minCVSS,
		},
	}
}
