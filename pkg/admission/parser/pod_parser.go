package parser

import (
	"encoding/json"
	"fmt"
	"scanco/pkg/admission"

	corev1 "k8s.io/api/core/v1"
)

// PodSpecParser extracts container images from pod specs
type PodSpecParser struct{}

// NewPodSpecParser creates a new pod spec parser
func NewPodSpecParser() *PodSpecParser {
	return &PodSpecParser{}
}

// ExtractImagesFromPodSpec extracts all container images from a pod spec
func (p *PodSpecParser) ExtractImagesFromPodSpec(podSpec *corev1.PodSpec) []admission.ImageReference {
	var images []admission.ImageReference

	// Extract from init containers
	for _, container := range podSpec.InitContainers {
		if ref := parseImageReference(container.Image); ref != nil {
			images = append(images, *ref)
		}
	}

	// Extract from regular containers
	for _, container := range podSpec.Containers {
		if ref := parseImageReference(container.Image); ref != nil {
			images = append(images, *ref)
		}
	}

	// Extract from ephemeral containers
	for _, container := range podSpec.EphemeralContainers {
		if ref := parseImageReference(container.Image); ref != nil {
			images = append(images, *ref)
		}
	}

	return images
}

// ExtractImagesFromRawObject extracts images from any Kubernetes object containing a pod spec
func (p *PodSpecParser) ExtractImagesFromRawObject(raw []byte) ([]admission.ImageReference, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %v", err)
	}

	// Extract pod spec based on resource type
	var podSpec *corev1.PodSpec
	switch kind := obj["kind"].(string); kind {
	case "Pod":
		pod := &corev1.Pod{}
		if err := json.Unmarshal(raw, pod); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Pod: %v", err)
		}
		podSpec = &pod.Spec

	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		// These types have a template.spec that contains the pod spec
		spec, ok := obj["spec"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid spec for %s", kind)
		}
		template, ok := spec["template"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid template for %s", kind)
		}
		rawTemplate, err := json.Marshal(template)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal template: %v", err)
		}

		pod := &corev1.Pod{}
		if err := json.Unmarshal(rawTemplate, pod); err != nil {
			return nil, fmt.Errorf("failed to unmarshal template: %v", err)
		}
		podSpec = &pod.Spec

	default:
		return nil, fmt.Errorf("unsupported resource type: %s", kind)
	}

	return p.ExtractImagesFromPodSpec(podSpec), nil
}

// parseImageReference parses an image string into structured data
func parseImageReference(image string) *admission.ImageReference {
	return ParseImageReference(image)
}
 