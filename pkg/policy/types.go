package policy

import (
	"fmt"
	"strings"

	"scanco/pkg/vulnerability"
)

// Severity represents a severity level
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// UnmarshalYAML implements yaml.Unmarshaler for custom severity validation
func (s *Severity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}

	// Convert to uppercase for comparison
	str = strings.ToUpper(str)
	switch str {
	case string(SeverityCritical), string(SeverityHigh),
		string(SeverityMedium), string(SeverityLow), string(SeverityNone):
		*s = Severity(str)
		return nil
	default:
		return fmt.Errorf("invalid severity level: %s", str)
	}
}

// Policy represents a security policy for container scanning
type Policy struct {
	Name string `yaml:"name"`
	// Metadata about the policy
	Metadata struct {
		Description string `yaml:"description"`
		Author      string `yaml:"author,omitempty"`
		Version     string `yaml:"version,omitempty"`
	} `yaml:"metadata"`

	// Rules for container scanning
	Rules struct {
		// Maximum allowed severity level
		MaxSeverity Severity `yaml:"max_severity"`

		// List of specific CVEs to block
		BlockedCVEs []string `yaml:"blocked_cves,omitempty"`

		// List of allowed base images (whitelist)
		AllowedBaseImages []string `yaml:"allowed_base_images,omitempty"`

		// Optional: Minimum CVSS score to block (0-10)
		MinCVSS *float64 `yaml:"min_cvss,omitempty"`
	} `yaml:"rules"`
}

// Validate checks if a policy is valid
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if p.Metadata.Description == "" {
		return fmt.Errorf("policy description is required")
	}

	// Validate CVE IDs format
	for _, cve := range p.Rules.BlockedCVEs {
		if !strings.HasPrefix(cve, "CVE-") {
			return fmt.Errorf("invalid CVE ID format: %s", cve)
		}
	}

	// Validate CVSS score range
	if p.Rules.MinCVSS != nil {
		if *p.Rules.MinCVSS < 0 || *p.Rules.MinCVSS > 10 {
			return fmt.Errorf("min_cvss must be between 0 and 10")
		}
	}

	return nil
}

// IsImageAllowed checks if an image is allowed by the policy
func (p *Policy) IsImageAllowed(imageName string) bool {
	// If no allowed images specified, all images are allowed
	if len(p.Rules.AllowedBaseImages) == 0 {
		return true
	}

	// Check if image matches any allowed pattern
	for _, allowed := range p.Rules.AllowedBaseImages {
		if allowed == imageName {
			return true
		}
		// Support wildcard matching (e.g., "nginx:*")
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(imageName, prefix) {
				return true
			}
		}
	}

	return false
}

// IsVulnerabilityAllowed checks if a vulnerability is allowed by the policy
func (p *Policy) IsVulnerabilityAllowed(vuln vulnerability.Vulnerability) bool {
	// Check blocked CVEs
	for _, blockedCVE := range p.Rules.BlockedCVEs {
		if vuln.ID == blockedCVE {
			return false
		}
	}

	// Check CVSS score
	if p.Rules.MinCVSS != nil && vuln.CVSS >= *p.Rules.MinCVSS {
		return false
	}

	// Check severity level
	severityLevels := map[vulnerability.Severity]int{
		vulnerability.SeverityCritical: 4,
		vulnerability.SeverityHigh:     3,
		vulnerability.SeverityMedium:   2,
		vulnerability.SeverityLow:      1,
		vulnerability.SeverityNone:     0,
	}

	maxLevel := severityLevels[vulnerability.Severity(p.Rules.MaxSeverity)]
	vulnLevel := severityLevels[vuln.Severity]

	return vulnLevel <= maxLevel
}
