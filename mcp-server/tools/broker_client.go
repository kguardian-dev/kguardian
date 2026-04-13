package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kguardian-dev/kguardian/mcp-server/logger"
	"github.com/sirupsen/logrus"
)

// maxResponseBytes is the maximum size of a broker response body (10 MB).
const maxResponseBytes = 10 * 1024 * 1024

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
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: 30 * time.Second,
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
	defer resp.Body.Close()

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
