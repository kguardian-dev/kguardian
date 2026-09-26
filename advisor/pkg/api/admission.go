package api

import (
	"net/url"
)

// AdmissionPolicyOptions select GET /attestations/policy.
type AdmissionPolicyOptions struct {
	// Format: kyverno, policy-controller or kguardian.
	Format string
	// Mode: audit or enforce.
	Mode string
	// Namespace narrows the images to one namespace ("" = cluster).
	Namespace string
	// AcknowledgePartial generates an enforcing policy although some
	// running images are not covered.
	AcknowledgePartial bool
}

// GetAdmissionPolicyFunc is replaceable in tests.
var GetAdmissionPolicyFunc = getRealAdmissionPolicy

// GetAdmissionPolicy returns the generated policy YAML.
func GetAdmissionPolicy(o AdmissionPolicyOptions) ([]byte, error) {
	return GetAdmissionPolicyFunc(o)
}

func getRealAdmissionPolicy(o AdmissionPolicyOptions) ([]byte, error) {
	q := url.Values{}
	if o.Format != "" {
		q.Set("format", o.Format)
	}
	if o.Mode != "" {
		q.Set("mode", o.Mode)
	}
	if o.Namespace != "" {
		q.Set("namespace", o.Namespace)
	}
	if o.AcknowledgePartial {
		q.Set("acknowledgePartial", "true")
	}
	path := "/attestations/policy"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return brokerGetBody("GetAdmissionPolicy", path)
}
