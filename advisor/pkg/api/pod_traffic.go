package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	log "github.com/rs/zerolog/log"

	v1 "k8s.io/api/core/v1"
)

type PodTraffic struct {
	UUID string `yaml:"uuid" json:"uuid"`
	// Source pod fields - represent the target pod for which we're generating the policy
	SrcPodName   string `yaml:"pod_name" json:"pod_name"`           // Name of the target pod
	SrcIP        string `yaml:"pod_ip" json:"pod_ip"`               // IP of the target pod
	SrcNamespace string `yaml:"pod_namespace" json:"pod_namespace"` // Namespace of the target pod
	SrcPodPort   string `yaml:"pod_port" json:"pod_port"`           // Port on the target pod (used for INGRESS rules)

	// Traffic metadata
	TrafficType string `yaml:"traffic_type" json:"traffic_type"` // "INGRESS" or "EGRESS" relative to the target pod

	// Destination/peer fields - represent the remote entity communicating with the target pod
	DstIP   string `yaml:"traffic_in_out_ip" json:"traffic_in_out_ip"`     // IP of the peer (external entity)
	DstPort string `yaml:"traffic_in_out_port" json:"traffic_in_out_port"` // Port on the peer (used for EGRESS rules)

	Protocol v1.Protocol `yaml:"ip_protocol" json:"ip_protocol"` // Network protocol (TCP, UDP, etc.)
}

type PodDetail struct {
	UUID      string `yaml:"uuid" json:"uuid"`
	PodIP     string `yaml:"pod_ip" json:"pod_ip"`
	Name      string `yaml:"pod_name" json:"pod_name"`
	Namespace string `yaml:"pod_namespace" json:"pod_namespace"`
	Pod       v1.Pod `yaml:"pod_obj" json:"pod_obj"`
}

type SvcDetail struct {
	SvcIp        string     `yaml:"svc_ip" json:"svc_ip"`
	SvcName      string     `yaml:"svc_name" json:"svc_name"`
	SvcNamespace string     `yaml:"svc_namespace" json:"svc_namespace"`
	Service      v1.Service `yaml:"service_spec" json:"service_spec"`
}

// BrokerBaseURL is the base URL of the kguardian broker. It defaults to the
// port-forward target the kubectl-plugin CLI sets up (a forward to
// localhost:9090). The `serve` command overrides it (from BROKER_URL) so the
// in-cluster service reaches the broker directly without a port-forward.
//
// BrokerBaseURL and BrokerAuthToken are configure-once values: set them before
// serving traffic (the CLI sets up the port-forward first; `serve` sets them
// from the environment before ListenAndServe). They are only read afterwards,
// so concurrent broker calls need no synchronisation.
var BrokerBaseURL = "http://127.0.0.1:9090"

// BrokerAuthToken, when non-empty, is sent as a Bearer token on every broker
// request. The broker requires it on all data endpoints when deployed with
// BROKER_AUTH_TOKEN set; the `serve` command wires it from the environment so
// the in-cluster service authenticates the same way the mcp-server does.
var BrokerAuthToken = ""

// maxBrokerResponseBytes caps the broker response body read (10 MB) so a
// long-lived `serve` process can't be OOM'd by an oversized/hostile response.
const maxBrokerResponseBytes = 10 * 1024 * 1024

// brokerHTTPClient bounds every broker call with a timeout so a hung broker
// can't pin a goroutine until the serve WriteTimeout fires.
var brokerHTTPClient = &http.Client{Timeout: 30 * time.Second}

// brokerGet performs an authenticated, timeout-bounded GET against the broker.
// path is the URL path (already escaped by the caller) appended to
// BrokerBaseURL. Callers are responsible for closing the returned body.
func brokerGet(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, BrokerBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if BrokerAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+BrokerAuthToken)
	}
	return brokerHTTPClient.Do(req)
}

// Function variables for easier mocking in tests
var (
	GetPodTrafficFunc = getRealPodTraffic
	GetPodSpecFunc    = getRealPodSpec
	GetSvcSpecFunc    = getRealSvcSpec
)

// GetPodTraffic gets pod traffic information
func GetPodTraffic(podName string) ([]PodTraffic, error) {
	return GetPodTrafficFunc(podName)
}

// GetPodSpec gets pod specification
func GetPodSpec(podIP string) (*PodDetail, error) {
	return GetPodSpecFunc(podIP)
}

// GetSvcSpec gets service specification
func GetSvcSpec(svcIP string) (*SvcDetail, error) {
	return GetSvcSpecFunc(svcIP)
}

// Real implementations
func getRealPodTraffic(podName string) ([]PodTraffic, error) {
	// PathEscape the caller-supplied name so a value containing '/', '?', '#'
	// or control chars can't manipulate the broker request path/query.
	resp, err := brokerGet("/pod/traffic/" + url.PathEscape(podName))
	if err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetPodTraffic: Error closing response body")
		}
	}()
	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetPodTraffic: received non-OK HTTP status code: %v", resp.StatusCode)
	}
	var podTraffic []PodTraffic

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokerResponseBytes))
	if err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error reading response body")
		return nil, err
	}

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.Unmarshal([]byte(body), &podTraffic); err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error unmarshal JSON")
		return nil, err
	}

	// If no pod traffic is found, return err
	if len(podTraffic) == 0 {
		return nil, fmt.Errorf("GetPodTraffic: No pod traffic found in database")
	}

	return podTraffic, nil
}

// Should we just get the pod spec directly from the cluster and only use the DB for the SaaS version where it contains the pod spec? Would this help with reducing unnecessary chatter?And just let the client do it?
func getRealPodSpec(ip string) (*PodDetail, error) {
	resp, err := brokerGet("/pod/ip/" + url.PathEscape(ip))
	if err != nil {
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("getRealPodSpec: Error closing response body")
		}
	}()

	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		log.Debug().Msgf("received non-OK HTTP status code: %v", resp.StatusCode)
		return nil, nil
	}

	var details *PodDetail

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerResponseBytes)).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	// If no pod details are found, return err
	if details == nil {
		return nil, fmt.Errorf("no pod details found in database")
	}

	return details, nil
}

func getRealSvcSpec(svcIp string) (*SvcDetail, error) {
	resp, err := brokerGet("/svc/ip/" + url.PathEscape(svcIp))
	if err != nil {
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("getRealSvcSpec: Error closing response body")
		}
	}()

	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		log.Debug().Msgf("received non-OK HTTP status code: %v", resp.StatusCode)
		return nil, nil
	}

	var details SvcDetail

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerResponseBytes)).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	return &details, nil
}
