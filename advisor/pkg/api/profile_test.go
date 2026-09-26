package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withBroker(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	origURL, origTok := BrokerBaseURL, BrokerAuthToken
	BrokerBaseURL, BrokerAuthToken = srv.URL, "tok"
	t.Cleanup(func() {
		srv.Close()
		BrokerBaseURL, BrokerAuthToken = origURL, origTok
	})
}

func TestGetProfile_EscapesSegmentsAndSendsToken(t *testing.T) {
	var gotPath, gotAuth string
	withBroker(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"posture":{"status":"unknown","score":null,"coverage":0,"grade":null,"unknownDimensions":[]},"dimensions":{}}`))
	})
	p, _, err := GetProfile("a/b", "Deployment", "x?y")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if gotPath != "/workloads/a%2Fb/Deployment/x%3Fy/profile" {
		t.Errorf("path = %s", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q", gotAuth)
	}
	if p.Posture.Score != nil {
		t.Error("null score must decode as nil (unknown), not 0")
	}
}

func TestGetProfile_404CarriesBrokerCode(t *testing.T) {
	withBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"workload_not_found","message":"no data for payments/Deployment/x"}`))
	})
	_, _, err := GetProfile("payments", "Deployment", "x")
	var nf *NotFoundError
	if !errors.Is(err, ErrNotFound) || !errors.As(err, &nf) || nf.Code != "workload_not_found" {
		t.Fatalf("want NotFoundError workload_not_found, got %v", err)
	}
}

func TestGetProfileDiff_OmitsZeroRevisions(t *testing.T) {
	var q string
	withBroker(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"changed":false,"dimensions":{}}`))
	})
	if _, _, err := GetProfileDiff("n", "Deployment", "x", 0, 4); err != nil {
		t.Fatal(err)
	}
	if q != "to=4" {
		t.Errorf("query = %q", q)
	}
}

func TestGetImages_DecodesPage(t *testing.T) {
	withBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"digest":"sha256:a","repository":null,"tags":[],"digestKind":"config","firstSeen":"x","lastSeen":"y","runningContainers":0}],"nextAfter":null}`))
	})
	page, raw, err := GetImages(ImageListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Repository != nil || page.NextAfter != nil || len(raw) == 0 {
		t.Errorf("page = %+v", page)
	}
}
