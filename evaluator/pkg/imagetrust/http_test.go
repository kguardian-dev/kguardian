package imagetrust

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestImageTrustEndpointNeedsTheReadToken(t *testing.T) {
	r := &Runner{}
	r.store([]Result{{Policy: "shop/p", Namespace: "shop", Verdict: "WouldDeny"}, {Policy: "x/p", Namespace: "x", Verdict: "Trusted"}})
	h := r.Handler("read-token-0123456789")
	for _, auth := range []string{"", "Bearer wrong", "read-token-0123456789", "Basic read-token-0123456789"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/image-trust", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: %d", auth, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/image-trust?namespace=shop", nil)
	req.Header.Set("Authorization", "Bearer read-token-0123456789")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with token: %d", rec.Code)
	}
	var body struct {
		EvaluatedAt *time.Time `json:"evaluatedAt"`
		Results     []Result   `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Results) != 1 || body.Results[0].Namespace != "shop" {
		t.Fatalf("body = %s, %v", rec.Body.String(), err)
	}
	// Broker auth off: no token to check, open like the broker.
	rec = httptest.NewRecorder()
	r.Handler("").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/image-trust", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("auth off: %d", rec.Code)
	}
}
