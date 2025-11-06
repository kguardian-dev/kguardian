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
	// Broker expects just the pod name in the URL
	url := fmt.Sprintf("%s/pod/traffic/%s", c.baseURL, podName)
	return c.get(url)
}

// GetPodSyscalls retrieves syscall data for a pod
func (c *BrokerClient) GetPodSyscalls(namespace, podName string) (interface{}, error) {
	// Broker expects just the pod name in the URL
	url := fmt.Sprintf("%s/pod/syscalls/%s", c.baseURL, podName)
	return c.get(url)
}

// GetPodByIP retrieves pod details by IP address
func (c *BrokerClient) GetPodByIP(ip string) (interface{}, error) {
	url := fmt.Sprintf("%s/pod/ip/%s", c.baseURL, ip)
	return c.get(url)
}

// GetServiceByIP retrieves service details by IP address
func (c *BrokerClient) GetServiceByIP(ip string) (interface{}, error) {
	url := fmt.Sprintf("%s/svc/ip/%s", c.baseURL, ip)
	return c.get(url)
}

// GetAllPodTraffic retrieves all pod traffic in the cluster
func (c *BrokerClient) GetAllPodTraffic() (interface{}, error) {
	url := fmt.Sprintf("%s/pod/traffic", c.baseURL)
	return c.get(url)
}

// GetAllPods retrieves all pod details in the cluster
func (c *BrokerClient) GetAllPods() (interface{}, error) {
	url := fmt.Sprintf("%s/pod/info", c.baseURL)
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
