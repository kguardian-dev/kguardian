package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/sirupsen/logrus"
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
			Timeout: 90 * time.Second, // Allow enough time for cluster-wide queries
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
	startTime := time.Now()

	logger.Log.WithFields(logrus.Fields{
		"url":     url,
		"timeout": c.httpClient.Timeout.String(),
	}).Debug("Making broker request")

	resp, err := c.httpClient.Get(url)
	requestDuration := time.Since(startTime)

	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"url":              url,
			"error":            err.Error(),
			"request_duration": requestDuration.String(),
			"timeout":          c.httpClient.Timeout.String(),
		}).Error("Broker request failed")
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	logger.Log.WithFields(logrus.Fields{
		"url":              url,
		"status_code":      resp.StatusCode,
		"request_duration": requestDuration.String(),
	}).Debug("Received broker response")

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.Log.WithFields(logrus.Fields{
			"url":              url,
			"status_code":      resp.StatusCode,
			"response_body":    string(body),
			"request_duration": requestDuration.String(),
		}).Error("Broker returned non-OK status")
		return nil, fmt.Errorf("broker returned status %d: %s", resp.StatusCode, string(body))
	}

	decodeStart := time.Now()
	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		decodeDuration := time.Since(decodeStart)
		logger.Log.WithFields(logrus.Fields{
			"url":              url,
			"error":            err.Error(),
			"decode_duration":  decodeDuration.String(),
			"request_duration": requestDuration.String(),
		}).Error("Failed to decode broker response")
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	decodeDuration := time.Since(decodeStart)
	totalDuration := time.Since(startTime)

	logger.Log.WithFields(logrus.Fields{
		"url":              url,
		"status_code":      resp.StatusCode,
		"request_duration": requestDuration.String(),
		"decode_duration":  decodeDuration.String(),
		"total_duration":   totalDuration.String(),
	}).Info("Broker request completed successfully")

	return result, nil
}
