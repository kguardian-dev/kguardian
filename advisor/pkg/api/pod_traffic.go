package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/rs/zerolog/log"

	v1 "k8s.io/api/core/v1"
)

// Sentinel errors for distinct API failure modes.
var (
	ErrNotFound          = errors.New("resource not found")
	ErrBrokerUnavailable = errors.New("broker unavailable")
	ErrTimeout           = errors.New("request timeout")
)

// httpClient is a package-level shared client with connection pooling and a
// default timeout. Individual call-sites may still wrap it with a context.
var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
	Timeout: 30 * time.Second,
}

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

// classifyStatusError maps an HTTP status code to a sentinel error.
func classifyStatusError(statusCode int) error {
	if statusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if statusCode >= 500 {
		return ErrBrokerUnavailable
	}
	return fmt.Errorf("unexpected HTTP status: %d", statusCode)
}

// Real implementations
func getRealPodTraffic(podName string) ([]PodTraffic, error) {
	apiURL := "http://127.0.0.1:9090/pod/traffic/" + podName

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("GetPodTraffic: failed to build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			log.Error().Err(err).Msg("GetPodTraffic: request timed out")
			return nil, ErrTimeout
		}
		log.Error().Err(err).Msg("GetPodTraffic: Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetPodTraffic: Error closing response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, classifyStatusError(resp.StatusCode)
	}

	var podTraffic []PodTraffic

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error reading response body")
		return nil, err
	}

	if err := json.Unmarshal(body, &podTraffic); err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error unmarshal JSON")
		return nil, err
	}

	if len(podTraffic) == 0 {
		return nil, fmt.Errorf("GetPodTraffic: No pod traffic found in database")
	}

	return podTraffic, nil
}

// Should we just get the pod spec directly from the cluster and only use the DB for the SaaS version where it contains the pod spec? Would this help with reducing unnecessary chatter?And just let the client do it?
func getRealPodSpec(ip string) (*PodDetail, error) {
	apiURL := "http://127.0.0.1:9090/pod/ip/" + ip

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getRealPodSpec: failed to build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			log.Error().Err(err).Msg("getRealPodSpec: request timed out")
			return nil, ErrTimeout
		}
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("getRealPodSpec: Error closing response body")
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		log.Debug().Msgf("getRealPodSpec: resource not found (404) for IP %s", ip)
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, classifyStatusError(resp.StatusCode)
	}

	var details *PodDetail

	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	if details == nil {
		return nil, fmt.Errorf("no pod details found in database")
	}

	return details, nil
}

func getRealSvcSpec(svcIp string) (*SvcDetail, error) {
	apiURL := "http://127.0.0.1:9090/svc/ip/" + svcIp

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getRealSvcSpec: failed to build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			log.Error().Err(err).Msg("getRealSvcSpec: request timed out")
			return nil, ErrTimeout
		}
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("getRealSvcSpec: Error closing response body")
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		log.Debug().Msgf("getRealSvcSpec: resource not found (404) for IP %s", svcIp)
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, classifyStatusError(resp.StatusCode)
	}

	var details SvcDetail

	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	return &details, nil
}
