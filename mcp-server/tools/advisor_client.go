package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/sirupsen/logrus"
)

// defaultAdvisorURL is the in-cluster address of the advisor service (the
// `advisor serve` command). Overridable via ADVISOR_URL.
const defaultAdvisorURL = "http://kguardian-advisor.kguardian.svc.cluster.local:8083"

// AdvisorClient talks to the advisor HTTP service, which synthesises
// NetworkPolicy / CiliumNetworkPolicy YAML and seccomp JSON from observed
// runtime data. Unlike BrokerClient it returns the raw response body (YAML or
// JSON text) rather than decoding it — the generated artifact is presented to
// the user verbatim.
type AdvisorClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewAdvisorClient resolves the advisor base URL from the argument, then
// ADVISOR_URL, then the in-cluster default — mirroring BrokerClient's
// defensive trimming of surrounding whitespace and trailing slashes.
func NewAdvisorClient(baseURL string) *AdvisorClient {
	resolved := strings.TrimSpace(baseURL)
	if resolved == "" {
		resolved = strings.TrimSpace(os.Getenv("ADVISOR_URL"))
	}
	if resolved == "" {
		resolved = defaultAdvisorURL
	}
	return &AdvisorClient{
		baseURL: strings.TrimRight(resolved, "/"),
		httpClient: &http.Client{
			// Policy synthesis fans out to several broker lookups per peer,
			// so allow generous time without blocking the MCP request forever.
			Timeout: 60 * time.Second,
		},
	}
}

// GenerateNetworkPolicy returns the YAML for the requested pod's network policy.
// policyType is "kubernetes" (default) or "cilium".
func (c *AdvisorClient) GenerateNetworkPolicy(ctx context.Context, podName, policyType string) (string, error) {
	q := url.Values{}
	q.Set("pod", podName)
	if policyType != "" {
		q.Set("type", policyType)
	}
	return c.getText(ctx, "/generate/networkpolicy?"+q.Encode())
}

// GenerateSeccompProfile returns the JSON seccomp profile for the requested pod.
func (c *AdvisorClient) GenerateSeccompProfile(ctx context.Context, podName string) (string, error) {
	q := url.Values{}
	q.Set("pod", podName)
	return c.getText(ctx, "/generate/seccomp?"+q.Encode())
}

// getText performs a GET and returns the response body as a string. On a
// non-200 it extracts the advisor's `{"error": "..."}` message when present.
func (c *AdvisorClient) getText(ctx context.Context, path string) (string, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{"url": reqURL, "error": err.Error()}).Error("Advisor request failed")
		return "", fmt.Errorf("failed to reach advisor: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read advisor response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Advisor errors are JSON: {"error": "..."}. Surface the message if we
		// can parse it, otherwise the raw body.
		var parsed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
			return "", fmt.Errorf("advisor returned %d: %s", resp.StatusCode, parsed.Error)
		}
		return "", fmt.Errorf("advisor returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return string(body), nil
}
