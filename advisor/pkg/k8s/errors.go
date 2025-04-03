package k8s

import (
	"errors"
)

// Common error definitions for the k8s package
var (
	ErrNoClientset  = errors.New("no Kubernetes clientset available")
	ErrInvalidInput = errors.New("invalid input parameters")
	ErrNoConfig     = errors.New("no Kubernetes configuration available")
)
