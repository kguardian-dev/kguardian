package network

import api "github.com/kguardian-dev/kguardian/advisor/pkg/api"

// BrokerData is the broker read surface that policy synthesis depends on:
// fetching a pod's observed traffic, and resolving a peer IP to its pod or
// service identity. Injecting it (rather than calling the api package's
// process-global accessors directly) decouples the generators and PolicyService
// from package-global state and makes peer resolution mockable in tests.
type BrokerData interface {
	// PodTrafficByName returns the observed traffic baseline for a pod.
	PodTrafficByName(name string) ([]api.PodTraffic, error)
	// PodByIP resolves a peer IP to a pod (nil, nil if not a known pod).
	PodByIP(ip string) (*api.PodDetail, error)
	// ServiceByIP resolves a peer IP to a service (nil, nil if not a known svc).
	ServiceByIP(ip string) (*api.SvcDetail, error)
}

// apiBrokerData is the default BrokerData, backed by the api package's
// configured broker client (the CLI's port-forward target, or the URL/token the
// `serve` command sets). It bridges the new dependency-injection seam to the
// existing api accessors so current callers keep working unchanged.
type apiBrokerData struct{}

func (apiBrokerData) PodTrafficByName(name string) ([]api.PodTraffic, error) {
	return api.GetPodTraffic(name)
}
func (apiBrokerData) PodByIP(ip string) (*api.PodDetail, error)     { return api.GetPodSpec(ip) }
func (apiBrokerData) ServiceByIP(ip string) (*api.SvcDetail, error) { return api.GetSvcSpec(ip) }

// DefaultBrokerData returns the api-backed BrokerData used when none is injected.
func DefaultBrokerData() BrokerData { return apiBrokerData{} }

// brokerDataAware is implemented by generators that accept an injected
// BrokerData, so PolicyService can propagate its data source to them.
type brokerDataAware interface {
	setBrokerData(BrokerData)
}
