package policy

import (
	"fmt"

	"scanco/pkg/vulnerability"
)

// EvaluationResult represents the result of a policy evaluation
type EvaluationResult struct {
	Allowed    bool
	Violations []Violation
	PolicyName string
}

// Violation represents a policy violation
type Violation struct {
	Type        string // "severity", "cve", "image", "cvss"
	Description string
	Details     map[string]interface{}
}

// Evaluator handles policy evaluation
type Evaluator struct {
	policies []*Policy
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator(policies []*Policy) *Evaluator {
	if len(policies) == 0 {
		// Use default policy if none provided
		policies = []*Policy{DefaultPolicy()}
	}
	return &Evaluator{
		policies: policies,
	}
}

// EvaluateImage checks if an image and its vulnerabilities comply with policies
func (e *Evaluator) EvaluateImage(imageName string, vulns []vulnerability.VulnerabilityResult) *EvaluationResult {
	// Check each policy
	for _, policy := range e.policies {
		result := &EvaluationResult{
			Allowed:    true,
			PolicyName: policy.Name,
		}

		// Check if image is allowed
		if !policy.IsImageAllowed(imageName) {
			result.Allowed = false
			result.Violations = append(result.Violations, Violation{
				Type:        "image",
				Description: fmt.Sprintf("Image %s is not in the allowed base images list", imageName),
				Details: map[string]interface{}{
					"image":          imageName,
					"allowed_images": policy.Rules.AllowedBaseImages,
				},
			})
		}

		// Check each vulnerability
		for _, vuln := range vulns {
			if !policy.IsVulnerabilityAllowed(vuln.Vulnerability) {
				result.Allowed = false

				// Determine violation type
				var violationType string
				var description string

				// Check if it's a blocked CVE
				for _, blockedCVE := range policy.Rules.BlockedCVEs {
					if vuln.Vulnerability.ID == blockedCVE {
						violationType = "cve"
						description = fmt.Sprintf("Found blocked CVE: %s", blockedCVE)
						break
					}
				}

				// Check severity
				if violationType == "" {
					severityLevels := map[vulnerability.Severity]int{
						vulnerability.SeverityCritical: 4,
						vulnerability.SeverityHigh:     3,
						vulnerability.SeverityMedium:   2,
						vulnerability.SeverityLow:      1,
						vulnerability.SeverityNone:     0,
					}

					maxLevel := severityLevels[vulnerability.Severity(policy.Rules.MaxSeverity)]
					vulnLevel := severityLevels[vuln.Vulnerability.Severity]

					if vulnLevel > maxLevel {
						violationType = "severity"
						description = fmt.Sprintf(
							"Vulnerability severity %s exceeds maximum allowed %s",
							vuln.Vulnerability.Severity,
							policy.Rules.MaxSeverity,
						)
					}
				}

				// Check CVSS score
				if violationType == "" && policy.Rules.MinCVSS != nil && vuln.Vulnerability.CVSS >= *policy.Rules.MinCVSS {
					violationType = "cvss"
					description = fmt.Sprintf(
						"CVSS score %.1f exceeds minimum threshold %.1f",
						vuln.Vulnerability.CVSS,
						*policy.Rules.MinCVSS,
					)
				}

				result.Violations = append(result.Violations, Violation{
					Type:        violationType,
					Description: description,
					Details: map[string]interface{}{
						"cve_id":      vuln.Vulnerability.ID,
						"severity":    vuln.Vulnerability.Severity,
						"cvss":        vuln.Vulnerability.CVSS,
						"package":     vuln.Package.Name,
						"version":     vuln.Package.Version,
						"description": vuln.Vulnerability.Description,
					},
				})
			}
		}

		// If any policy allows it, we're good
		if result.Allowed {
			return result
		}

		// If this policy denied it, return the violations
		if len(result.Violations) > 0 {
			return result
		}
	}

	// If we get here, no policy explicitly allowed or denied it
	return &EvaluationResult{
		Allowed:    false,
		PolicyName: "default",
		Violations: []Violation{{
			Type:        "policy",
			Description: "No policy explicitly allowed this image",
		}},
	}
}

// GetBlockedVulnerabilities returns vulnerabilities that are blocked by policies
func (e *Evaluator) GetBlockedVulnerabilities(vulns []vulnerability.VulnerabilityResult) []vulnerability.VulnerabilityResult {
	var blocked []vulnerability.VulnerabilityResult

	for _, vuln := range vulns {
		// Check each policy
		for _, policy := range e.policies {
			if !policy.IsVulnerabilityAllowed(vuln.Vulnerability) {
				blocked = append(blocked, vuln)
				break // No need to check other policies
			}
		}
	}

	return blocked
}

// GetAllowedVulnerabilities returns vulnerabilities that are allowed by policies
func (e *Evaluator) GetAllowedVulnerabilities(vulns []vulnerability.VulnerabilityResult) []vulnerability.VulnerabilityResult {
	var allowed []vulnerability.VulnerabilityResult

	for _, vuln := range vulns {
		// Check if any policy allows it
		isAllowed := false
		for _, policy := range e.policies {
			if policy.IsVulnerabilityAllowed(vuln.Vulnerability) {
				isAllowed = true
				break
			}
		}
		if isAllowed {
			allowed = append(allowed, vuln)
		}
	}

	return allowed
}
