package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"scanco/pkg/admission"

	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
)

// Server represents the admission webhook server
type Server struct {
	config  *admission.Config
	handler admission.AdmissionHandler
	logger  *logrus.Logger
}

// NewServer creates a new admission webhook server
func NewServer(config *admission.Config, handler admission.AdmissionHandler, logger *logrus.Logger) *Server {
	return &Server{
		config:  config,
		handler: handler,
		logger:  logger,
	}
}

// Start starts the webhook server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.serveValidate)
	mux.HandleFunc("/healthz", s.serveHealth)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.Port),
		Handler: mux,
	}

	s.logger.Infof("Starting admission webhook server on port %d", s.config.Port)
	return server.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) serveValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Errorf("Failed to read request body: %v", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}

	// Parse AdmissionReview
	admissionReview := &admissionv1.AdmissionReview{}
	if err := json.Unmarshal(body, admissionReview); err != nil {
		s.logger.Errorf("Failed to decode admission review: %v", err)
		http.Error(w, "failed to decode request", http.StatusBadRequest)
		return
	}

	// Handle the admission request
	response := s.handler.Handle(admissionReview)

	// Prepare response
	admissionReview.Response = response
	resp, err := json.Marshal(admissionReview)
	if err != nil {
		s.logger.Errorf("Failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}
