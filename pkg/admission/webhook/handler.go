package webhook

import (
	"fmt"
	"scanco/pkg/admission/parser"
	"scanco/pkg/policy"
	"scanco/pkg/scanner/container"
	"scanco/pkg/vulnerability"

	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Handler implements the admission.AdmissionHandler interface
type Handler struct {
	parser      *parser.PodSpecParser
	scanner     *container.ImageScanner
	vulnScanner *vulnerability.Scanner
	evaluator   *policy.Evaluator
	logger      *logrus.Logger
}

// NewHandler creates a new admission webhook handler
func NewHandler(scanner *container.ImageScanner, vulnScanner *vulnerability.Scanner, evaluator *policy.Evaluator, logger *logrus.Logger) *Handler {
	return &Handler{
		parser:      parser.NewPodSpecParser(),
		scanner:     scanner,
		vulnScanner: vulnScanner,
		evaluator:   evaluator,
		logger:      logger,
	}
}

// Handle processes admission review requests
func (h *Handler) Handle(review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	request := review.Request
	if request == nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: "invalid request: no admission request provided",
			},
		}
	}

	// Extract images from the request
	images, err := h.parser.ExtractImagesFromRawObject(request.Object.Raw)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: fmt.Sprintf("failed to extract images: %v", err),
			},
		}
	}

	// Validate each image
	var messages []string
	allowed := true

	for _, image := range images {
		// First scan the image for packages
		packages, err := h.scanner.ScanImage(image.Original)
		if err != nil {
			h.logger.Errorf("Failed to scan image %s: %v", image.Original, err)
			messages = append(messages, fmt.Sprintf("Failed to scan image %s: %v", image.Original, err))
			allowed = false
			continue
		}

		// Then scan for vulnerabilities
		options := vulnerability.DefaultScanOptions()
		result, err := h.vulnScanner.ScanPackages(packages, options)
		if err != nil {
			h.logger.Errorf("Failed to scan for vulnerabilities in image %s: %v", image.Original, err)
			messages = append(messages, fmt.Sprintf("Failed to scan for vulnerabilities in image %s: %v", image.Original, err))
			allowed = false
			continue
		}

		// Evaluate against policies
		evalResult := h.evaluator.EvaluateImage(image.Original, result.Results)
		if !evalResult.Allowed {
			allowed = false
			messages = append(messages, fmt.Sprintf("Image %s failed policy check (%s):", image.Original, evalResult.PolicyName))
			for _, violation := range evalResult.Violations {
				messages = append(messages, fmt.Sprintf("  - %s: %s", violation.Type, violation.Description))
			}
		}
	}

	return &admissionv1.AdmissionResponse{
		UID:     request.UID,
		Allowed: allowed,
		Result: &metav1.Status{
			Message: formatMessages(messages),
		},
	}
}

func formatMessages(messages []string) string {
	if len(messages) == 0 {
		return "all images passed security validation"
	}

	result := "Image validation failed:\n"
	for _, msg := range messages {
		result += fmt.Sprintf("- %s\n", msg)
	}
	return result
}
 