package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunningImagesPagesAndFilters(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Path != "/images" || r.URL.Query().Get("limit") != "500" {
			http.Error(w, "bad request", 400)
			return
		}
		// Shape as served by broker/src/image_inventory.rs (camelCase).
		switch r.URL.Query().Get("after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []map[string]interface{}{
					{"digest": "sha256:aa", "repository": "docker.io/library/nginx", "tags": []string{"1.27"}, "digestKind": "index", "runningContainers": 3},
					{"digest": "sha256:bb", "repository": "ghcr.io/x/old", "tags": []string{}, "digestKind": "manifest", "runningContainers": 0},
				},
				"nextAfter": "sha256:bb",
			})
		case "sha256:bb":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"items":     []map[string]interface{}{{"digest": "sha256:cc", "repository": "ghcr.io/x/api", "digestKind": "unknown", "runningContainers": 1}},
				"nextAfter": nil,
			})
		}
	}))
	defer srv.Close()
	c, _ := NewReadClient(srv.URL, "sc-token")
	got, err := c.RunningImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Digest != "sha256:aa" || got[0].DigestKind != "index" || got[1].Repository != "ghcr.io/x/api" {
		t.Fatalf("%+v", got)
	}
	for _, a := range auth {
		if a != "Bearer sc-token" {
			t.Errorf("auth %q", a)
		}
	}
}

func TestRunningImagesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing scope read", http.StatusForbidden)
	}))
	defer srv.Close()
	c, _ := NewReadClient(srv.URL, "t")
	if _, err := c.RunningImages(context.Background()); err == nil || Reason(err) != "http_403" {
		t.Fatalf("err %v", err)
	}
}
