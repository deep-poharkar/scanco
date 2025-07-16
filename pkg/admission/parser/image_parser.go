package parser

import (
	"scanco/pkg/admission"
	"strings"
)

// ParseImageReference parses a container image reference into its components
func ParseImageReference(image string) *admission.ImageReference {
	ref := &admission.ImageReference{
		Original: image,
	}

	// Split registry and rest
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		ref.Registry = parts[0]
		image = parts[1]
	} else {
		ref.Registry = "docker.io" // Default registry
	}

	// Split repository and tag/digest
	parts = strings.SplitN(image, "@", 2)
	if len(parts) == 2 {
		// Image has a digest
		ref.Repository = parts[0]
		ref.Digest = parts[1]
	} else {
		// Check for tag
		parts = strings.SplitN(image, ":", 2)
		ref.Repository = parts[0]
		if len(parts) == 2 {
			ref.Tag = parts[1]
		} else {
			ref.Tag = "latest" // Default tag
		}
	}

	// Handle official images (no namespace)
	if !strings.Contains(ref.Repository, "/") && ref.Registry == "docker.io" {
		ref.Repository = "library/" + ref.Repository
	}

	return ref
}
