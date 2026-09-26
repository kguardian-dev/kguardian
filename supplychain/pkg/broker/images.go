package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Image is one row of the broker's image inventory (GET /images).
type Image struct {
	Digest            string   `json:"digest"`
	Repository        string   `json:"repository"`
	Tags              []string `json:"tags"`
	DigestKind        string   `json:"digestKind"`
	RunningContainers int64    `json:"runningContainers"`
}

type imagePage struct {
	Items     []Image `json:"items"`
	NextAfter *string `json:"nextAfter"`
}

// maxInventoryPages bounds one full listing (500 per page).
const maxInventoryPages = 200

// maxPageBytes bounds one page response.
const maxPageBytes = 8 << 20

// ReadClient reads from the broker with a token that carries the read
// scope (the supplychain token does).
type ReadClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewReadClient returns a read client for the broker at baseURL.
func NewReadClient(baseURL, token string) (*ReadClient, error) {
	c, err := NewHTTPClient(baseURL, token)
	if err != nil {
		return nil, err
	}
	return &ReadClient{baseURL: c.baseURL, token: c.token, http: c.http}, nil
}

// RunningImages lists every image the inventory says is running now,
// following the cursor.
func (c *ReadClient) RunningImages(ctx context.Context) ([]Image, error) {
	var out []Image
	after := ""
	for page := 0; page < maxInventoryPages; page++ {
		q := url.Values{"limit": {strconv.Itoa(500)}}
		if after != "" {
			q.Set("after", after)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/images?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET /images: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, &StatusError{Path: "/images", StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), maxErrorBody)]))}
		}
		if len(body) > maxPageBytes {
			return nil, fmt.Errorf("GET /images: page exceeds %d bytes", maxPageBytes)
		}
		var p imagePage
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("GET /images: %w", err)
		}
		for _, im := range p.Items {
			if im.RunningContainers > 0 {
				out = append(out, im)
			}
		}
		if p.NextAfter == nil || *p.NextAfter == "" || *p.NextAfter == after {
			return out, nil
		}
		after = *p.NextAfter
	}
	return out, fmt.Errorf("GET /images: more than %d pages", maxInventoryPages)
}
