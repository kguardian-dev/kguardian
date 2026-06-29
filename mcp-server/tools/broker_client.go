package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/sirupsen/logrus"
)

// maxResponseBytes is the maximum size of a broker response body (10 MB).
const maxResponseBytes = 10 * 1024 * 1024

// BrokerClient handles communication with the kguardian broker
type BrokerClient struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewBrokerClient creates a new broker client.
//
// Sanitises baseURL defensively so a downstream fmt.Sprintf doesn't
// produce a malformed URL:
//   - Surrounding whitespace is trimmed. main.go already TrimSpace's
//     BROKER_URL before passing it here, but a future caller (test,
//     embedded SDK use, alternative config source) might not — and a
//     leading-space baseURL produces requests that http.NewRequest
//     rejects with the cryptic "net/url: invalid control character"
//     error, far from the env-var site that introduced the space.
//   - Trailing slashes are stripped. BROKER_URL="http://broker:9090/"
//     is a natural copy-paste artefact (operators copy from a browser
//     URL bar / dashboard). Most servers normalize the resulting
//     doubled slash but it shows up in logs as http://broker:9090//pod/...
//     and can confuse routing on prefix-matched reverse proxies.
func NewBrokerClient(baseURL string) *BrokerClient {
	return &BrokerClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		// Optional bearer token. When the broker is deployed with
		// BROKER_AUTH_TOKEN set, the mcp-server must present the same
		// token or its reads are rejected (401). Empty = no-auth, the
		// original behaviour.
		authToken: strings.TrimSpace(os.Getenv("BROKER_AUTH_TOKEN")),
		httpClient: &http.Client{
			Timeout: 90 * time.Second, // Allow enough time for cluster-wide queries
		},
	}
}

// GetPodNetworkTraffic retrieves network traffic data for a pod
func (c *BrokerClient) GetPodNetworkTraffic(ctx context.Context, podName string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/traffic/%s", c.baseURL, url.PathEscape(podName))
	return c.get(ctx, reqURL)
}

// GetPodSyscalls retrieves syscall data for a pod
func (c *BrokerClient) GetPodSyscalls(ctx context.Context, podName string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/syscalls/%s", c.baseURL, url.PathEscape(podName))
	return c.get(ctx, reqURL)
}

// GetPodByIP retrieves pod details by IP address
func (c *BrokerClient) GetPodByIP(ctx context.Context, ip string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/ip/%s", c.baseURL, url.PathEscape(ip))
	return c.get(ctx, reqURL)
}

// GetServiceByIP retrieves service details by IP address
func (c *BrokerClient) GetServiceByIP(ctx context.Context, ip string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/svc/ip/%s", c.baseURL, url.PathEscape(ip))
	return c.get(ctx, reqURL)
}

// GetAllPodTraffic retrieves all pod traffic in the cluster
func (c *BrokerClient) GetAllPodTraffic(ctx context.Context) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/traffic", c.baseURL)
	return c.get(ctx, reqURL)
}

// GetAllPods retrieves all pod details in the cluster
func (c *BrokerClient) GetAllPods(ctx context.Context) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/info", c.baseURL)
	return c.get(ctx, reqURL)
}

// GetPodByName retrieves pod details by pod name. The broker resolves
// the name cluster-wide, so the LLM can look a pod up directly from a
// name it already has (e.g. from a traffic record) instead of having
// to round-trip through an IP via GetPodByIP.
func (c *BrokerClient) GetPodByName(ctx context.Context, name string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/name/%s", c.baseURL, url.PathEscape(name))
	return c.get(ctx, reqURL)
}

// GetAllServices retrieves all service details in the cluster. Mirrors
// GetAllPods for the service inventory the LLM otherwise had no way to
// enumerate (GetServiceByIP only resolves a single known cluster IP).
func (c *BrokerClient) GetAllServices(ctx context.Context) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/svc/info", c.baseURL)
	return c.get(ctx, reqURL)
}

// GetPodsOnNode retrieves the pods the broker has recorded on a given node.
// Backs blast-radius / "what runs on node X" questions, which neither the
// namespace-scoped cluster pod list nor any per-pod lookup could answer.
func (c *BrokerClient) GetPodsOnNode(ctx context.Context, node string) (interface{}, error) {
	reqURL := fmt.Sprintf("%s/pod/list/%s", c.baseURL, url.PathEscape(node))
	return c.get(ctx, reqURL)
}

// GetAuditVerdicts retrieves policy-evaluation verdicts (Allow / WouldDeny)
// from the broker's /audit/verdicts endpoint. Filters are optional. The
// namespace dimension has three distinct modes that mirror the broker:
//   - clusterScoped=true  -> sends "namespace=" (empty value PRESENT), which
//     the broker reads as "cluster-scoped policy verdicts only" (those rows
//     are stored with an empty policy_namespace). Takes precedence over namespace.
//   - namespace != ""     -> sends "namespace=<ns>" (that namespace only).
//   - neither             -> omits the param entirely, spanning all
//     namespaces including cluster-scoped.
//
// The empty-vs-absent distinction is the whole reason clusterScoped is a
// separate flag: a bare empty string can't tell "all namespaces" apart from
// "cluster-scoped only", so the caller signals the latter explicitly.
func (c *BrokerClient) GetAuditVerdicts(ctx context.Context, policy, namespace, verdict, direction string, limit int, clusterScoped bool) (interface{}, error) {
	q := url.Values{}
	if policy != "" {
		q.Set("policy", policy)
	}
	if clusterScoped {
		q.Set("namespace", "") // empty value present -> cluster-scoped only
	} else if namespace != "" {
		q.Set("namespace", namespace)
	}
	if verdict != "" {
		q.Set("verdict", verdict)
	}
	if direction != "" {
		q.Set("direction", direction)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	reqURL := fmt.Sprintf("%s/audit/verdicts", c.baseURL)
	if encoded := q.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}
	return c.get(ctx, reqURL)
}

// get performs an HTTP GET request and returns the response
func (c *BrokerClient) get(ctx context.Context, reqURL string) (interface{}, error) {
	startTime := time.Now()

	logger.Log.WithFields(logrus.Fields{
		"url":     reqURL,
		"timeout": c.httpClient.Timeout.String(),
	}).Debug("Making broker request")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	requestDuration := time.Since(startTime)

	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"url":              reqURL,
			"error":            err.Error(),
			"request_duration": requestDuration.String(),
			"timeout":          c.httpClient.Timeout.String(),
		}).Error("Broker request failed")
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	logger.Log.WithFields(logrus.Fields{
		"url":              reqURL,
		"status_code":      resp.StatusCode,
		"request_duration": requestDuration.String(),
	}).Debug("Received broker response")

	limitedBody := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(limitedBody)
		logger.Log.WithFields(logrus.Fields{
			"url":              reqURL,
			"status_code":      resp.StatusCode,
			"response_body":    string(body),
			"request_duration": requestDuration.String(),
		}).Error("Broker returned non-OK status")
		return nil, fmt.Errorf("broker returned status %d: %s", resp.StatusCode, string(body))
	}

	decodeStart := time.Now()
	var result interface{}
	if err := json.NewDecoder(limitedBody).Decode(&result); err != nil {
		decodeDuration := time.Since(decodeStart)
		logger.Log.WithFields(logrus.Fields{
			"url":              reqURL,
			"error":            err.Error(),
			"decode_duration":  decodeDuration.String(),
			"request_duration": requestDuration.String(),
		}).Error("Failed to decode broker response")
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	decodeDuration := time.Since(decodeStart)
	totalDuration := time.Since(startTime)

	logger.Log.WithFields(logrus.Fields{
		"url":              reqURL,
		"status_code":      resp.StatusCode,
		"request_duration": requestDuration.String(),
		"decode_duration":  decodeDuration.String(),
		"total_duration":   totalDuration.String(),
	}).Info("Broker request completed successfully")

	return result, nil
}
