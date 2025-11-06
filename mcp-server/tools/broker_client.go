package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BrokerClient handles communication with the kguardian broker
type BrokerClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewBrokerClient creates a new broker client
func NewBrokerClient(baseURL string) *BrokerClient {
	return &BrokerClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetPodNetworkTraffic retrieves network traffic data for a pod
func (c *BrokerClient) GetPodNetworkTraffic(namespace, podName string) (interface{}, error) {
	url := fmt.Sprintf("%s/pod/traffic/name/%s/%s", c.baseURL, namespace, podName)
	return c.get(url)
}

// GetPodSyscalls retrieves syscall data for a pod
func (c *BrokerClient) GetPodSyscalls(namespace, podName string) (interface{}, error) {
	url := fmt.Sprintf("%s/pod/syscalls/name/%s/%s", c.baseURL, namespace, podName)
	return c.get(url)
}

// get performs an HTTP GET request and returns the response
func (c *BrokerClient) get(url string) (interface{}, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("broker returned status %d: %s", resp.StatusCode, string(body))
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}
