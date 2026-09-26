// Package appprofile reconciles ApplicationSecurityProfile resources: it
// reads each referenced workload's security profile from the broker
// (docs/design/workload-security-profile-api.md) and writes the result to
// the resource's status with server-side apply. It never writes spec,
// never creates or deletes resources, and never changes the workload.
package appprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Broker reads workload profiles. Implemented by BrokerClient; a fake in
// tests.
type Broker interface {
	Profile(ctx context.Context, namespace, kind, name string) (*Profile, error)
	Version(ctx context.Context, namespace, kind, name string, revision int64) (*Version, error)
}

// Profile is the subset of GET /workloads/{ns}/{kind}/{name}/profile the
// evaluator uses (contract section 2).
type Profile struct {
	ContentHash     string         `json:"contentHash"`
	Version         *VersionRef    `json:"version"`
	SnapshotPending bool           `json:"snapshotPending"`
	Posture         ProfilePosture `json:"posture"`
	Dimensions      map[string]Dim `json:"dimensions"`
	Findings        []Finding      `json:"findings"`
}

// VersionRef is the profile's pointer to the latest stored version.
type VersionRef struct {
	Revision    int64  `json:"revision"`
	ContentHash string `json:"contentHash"`
	CreatedAt   string `json:"createdAt"`
}

// ProfilePosture is the contract's posture rollup.
type ProfilePosture struct {
	Status            string          `json:"status"`
	Coverage          *float64        `json:"coverage"`
	UnknownDimensions []string        `json:"unknownDimensions"`
	Reasons           []PostureReason `json:"reasons"`
}

// PostureReason is one posture.reasons[] entry.
type PostureReason struct {
	Dimension string `json:"dimension"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// Dim is the common dimension envelope (contract 2.1).
type Dim struct {
	Status  string   `json:"status"`
	Reasons []Reason `json:"reasons"`
}

// Reason is a dimension reason: a stable code and a sentence.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Finding is one finding; only severity is used here.
type Finding struct {
	Severity string `json:"severity"`
}

// Version is GET .../profile/versions/{revision} (contract 3.2), minus
// the snapshot.
type Version struct {
	Revision        int64             `json:"revision"`
	ContentHash     string            `json:"contentHash"`
	CreatedAt       string            `json:"createdAt"`
	DimensionHashes map[string]string `json:"dimensionHashes"`
	Posture         struct {
		Status string `json:"status"`
	} `json:"posture"`
}

// BrokerError is a non-2xx broker response.
type BrokerError struct {
	StatusCode int
	// Code is the JSON "error" code on profile-route 404/400s
	// (workload_not_found, revision_not_found, bad_request); empty for
	// plain-text bodies.
	Code    string
	Message string
}

func (e *BrokerError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("broker returned %d %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("broker returned %d: %s", e.StatusCode, e.Message)
}

// errorCode returns the broker error code, or "" for other errors.
func errorCode(err error) string {
	var be *BrokerError
	if errors.As(err, &be) {
		return be.Code
	}
	return ""
}

func statusCode(err error) int {
	var be *BrokerError
	if errors.As(err, &be) {
		return be.StatusCode
	}
	return 0
}

// BrokerClient talks to the broker over HTTP with the READ-scope token.
type BrokerClient struct {
	base  string
	token string
	http  *http.Client
}

// NewBrokerClient builds a client. token may be empty when broker auth is
// off; when set it is sent as a Bearer token on every request.
func NewBrokerClient(baseURL, token string, timeout time.Duration) (*BrokerClient, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid broker URL %q", baseURL)
	}
	return &BrokerClient{
		base:  strings.TrimRight(u.String(), "/"),
		token: strings.TrimSpace(token),
		http:  &http.Client{Timeout: timeout},
	}, nil
}

func workloadPath(namespace, kind, name string) string {
	return "/workloads/" + url.PathEscape(namespace) + "/" + url.PathEscape(kind) + "/" + url.PathEscape(name)
}

// Profile fetches the live profile.
func (c *BrokerClient) Profile(ctx context.Context, namespace, kind, name string) (*Profile, error) {
	out := &Profile{}
	if err := c.get(ctx, workloadPath(namespace, kind, name)+"/profile", out); err != nil {
		return nil, err
	}
	return out, nil
}

// Version fetches one stored version.
func (c *BrokerClient) Version(ctx context.Context, namespace, kind, name string, revision int64) (*Version, error) {
	out := &Version{}
	p := workloadPath(namespace, kind, name) + "/profile/versions/" + strconv.FormatInt(revision, 10)
	if err := c.get(ctx, p, out); err != nil {
		return nil, err
	}
	return out, nil
}

// maxBody bounds how much of a response is read. A profile is tens of KB;
// 8 MiB is far above any legitimate response and stops a misbehaving
// endpoint from exhausting the evaluator's memory.
const maxBody = 8 << 20

func (c *BrokerClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		be := &BrokerError{StatusCode: resp.StatusCode}
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
			be.Code, be.Message = parsed.Error, parsed.Message
		} else {
			be.Message = strings.TrimSpace(string(body))
			if len(be.Message) > 200 {
				be.Message = be.Message[:200]
			}
		}
		return be
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding broker response for %s: %w", path, err)
	}
	return nil
}
