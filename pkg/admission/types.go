package admission

import (
	admissionv1 "k8s.io/api/admission/v1"
)

// Config holds the configuration for the admission controller
type Config struct {
	CertFile   string
	KeyFile    string
	Port       int
	PolicyFile string
}

// AdmissionHandler handles admission review requests
type AdmissionHandler interface {
	Handle(review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse
}

// ValidationResponse represents the result of image validation
type ValidationResponse struct {
	Allowed  bool
	Reason   string
	Warnings []string
}

// ImageReference contains parsed image information
type ImageReference struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	Original   string
}
