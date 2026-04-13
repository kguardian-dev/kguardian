package tools

import (
	"fmt"
	"net"
	"regexp"
)

// podNameRegexp matches RFC 1123 DNS subdomain names used for pod names.
// Allows lowercase alphanumeric characters, '-', and '.', must start and end
// with an alphanumeric character.
var podNameRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$`)

// namespaceRegexp matches RFC 1123 DNS label names used for namespaces.
// Allows lowercase alphanumeric characters and '-', must start and end with
// an alphanumeric character.
var namespaceRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)

// ValidatePodName validates a Kubernetes pod name against RFC 1123 DNS subdomain
// rules: lowercase alphanumeric, '-', and '.'; max 253 characters.
func ValidatePodName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("pod name must not be empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("pod name %q exceeds maximum length of 253 characters", name)
	}
	if !podNameRegexp.MatchString(name) {
		return fmt.Errorf("pod name %q is invalid: must match %s", name, podNameRegexp.String())
	}
	return nil
}

// ValidateNamespace validates a Kubernetes namespace name against RFC 1123 DNS
// label rules: lowercase alphanumeric and '-'; max 63 characters.
func ValidateNamespace(ns string) error {
	if len(ns) == 0 {
		return fmt.Errorf("namespace must not be empty")
	}
	if len(ns) > 63 {
		return fmt.Errorf("namespace %q exceeds maximum length of 63 characters", ns)
	}
	if !namespaceRegexp.MatchString(ns) {
		return fmt.Errorf("namespace %q is invalid: must match %s", ns, namespaceRegexp.String())
	}
	return nil
}

// ValidateIP validates that the given string is a valid IP address (v4 or v6).
func ValidateIP(ip string) error {
	if len(ip) == 0 {
		return fmt.Errorf("IP address must not be empty")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("IP address %q is invalid", ip)
	}
	return nil
}
