package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Image inventory reads (broker/src/image_inventory.rs): which image digests
// workloads run. Inventory only; there is no vulnerability, SBOM or
// signature data on these endpoints.

// ImageSummary is one row of GET /images.
type ImageSummary struct {
	Digest            string   `json:"digest"`
	Repository        *string  `json:"repository"`
	Tags              []string `json:"tags"`
	DigestKind        string   `json:"digestKind"`
	FirstSeen         string   `json:"firstSeen"`
	LastSeen          string   `json:"lastSeen"`
	RunningContainers int64    `json:"runningContainers"`
}

// ImagePage is the GET /images envelope. NextAfter is the cursor for the
// next page; nil on the last page.
type ImagePage struct {
	Items     []ImageSummary `json:"items"`
	NextAfter *string        `json:"nextAfter"`
}

// ImageUser is a workload container that runs (or ran) an image.
type ImageUser struct {
	ClusterID     string  `json:"clusterId"`
	Namespace     string  `json:"namespace"`
	WorkloadKind  string  `json:"workloadKind"`
	WorkloadName  string  `json:"workloadName"`
	ContainerName string  `json:"containerName"`
	ContainerKind string  `json:"containerKind"`
	ImageRef      string  `json:"imageRef"`
	FirstSeen     string  `json:"firstSeen"`
	LastSeen      string  `json:"lastSeen"`
	State         *string `json:"state"`
	StateReason   *string `json:"stateReason"`
	RanAsInit     bool    `json:"ranAsInit"`
	Running       bool    `json:"running"`
}

// ImageDetail is GET /images/{digest}.
type ImageDetail struct {
	Digest     string      `json:"digest"`
	Repository *string     `json:"repository"`
	Tags       []string    `json:"tags"`
	DigestKind string      `json:"digestKind"`
	FirstSeen  string      `json:"firstSeen"`
	LastSeen   string      `json:"lastSeen"`
	Workloads  []ImageUser `json:"workloads"`
	Truncated  bool        `json:"truncated"`
}

// ImageListOptions filters GET /images. Zero values are not sent.
type ImageListOptions struct {
	Namespace  string
	Repository string
	Limit      int
	After      string
}

// GetImagesFunc and GetImageFunc are swappable for tests that bypass HTTP.
var (
	GetImagesFunc = getRealImages
	GetImageFunc  = getRealImage
)

// GetImages fetches one page of the image inventory. It returns the decoded
// page and the raw body, so -o json can emit exactly what the broker said.
func GetImages(opts ImageListOptions) (*ImagePage, []byte, error) {
	return GetImagesFunc(opts)
}

// GetImage fetches one image and the workloads that run it.
func GetImage(digest string) (*ImageDetail, []byte, error) {
	return GetImageFunc(digest)
}

func getRealImages(opts ImageListOptions) (*ImagePage, []byte, error) {
	q := url.Values{}
	if opts.Namespace != "" {
		q.Set("namespace", opts.Namespace)
	}
	if opts.Repository != "" {
		q.Set("repository", opts.Repository)
	}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.After != "" {
		q.Set("after", opts.After)
	}
	path := "/images"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	body, err := brokerGetBody("GetImages", path)
	if err != nil {
		return nil, nil, err
	}
	var out ImagePage
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("GetImages: decoding response: %w", err)
	}
	return &out, body, nil
}

func getRealImage(digest string) (*ImageDetail, []byte, error) {
	body, err := brokerGetBody("GetImage", "/images/"+url.PathEscape(digest))
	if err != nil {
		return nil, nil, err
	}
	var out ImageDetail
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, fmt.Errorf("GetImage: decoding response: %w", err)
	}
	return &out, body, nil
}
