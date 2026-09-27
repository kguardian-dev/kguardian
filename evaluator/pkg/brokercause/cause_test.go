package brokercause

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type status int

func (s status) Error() string {
	return fmt.Sprintf("broker returned %d: http://10.1.2.3:8080", int(s))
}
func (s status) HTTPStatus() int { return int(s) }

func TestOf(t *testing.T) {
	// A broker behind TLS that the evaluator does not trust.
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsSrv.Config.ErrorLog = log.New(io.Discard, "", 0) // the handshake failure is the point
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	_, tlsErr := (&http.Client{Timeout: 2 * time.Second}).Get(tlsSrv.URL)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	_, dialErr := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + closed + "/x")

	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	_, timeoutErr := (&http.Client{Timeout: 50 * time.Millisecond}).Get(slow.URL)

	syn := json.Unmarshal([]byte("<html>"), &struct{}{})
	typ := json.Unmarshal([]byte(`{"a":"x"}`), &struct{ A int }{})

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "no error"},
		{"status", fmt.Errorf("wrapped: %w", status(503)), "status 503"},
		{"too large", fmt.Errorf("page larger than 1 bytes: %w", ErrTooLarge), "response too large"},
		{"untrusted TLS certificate", tlsErr, "TLS verification failed"},
		{"closed port", dialErr, "connection failed"},
		{"client timeout", timeoutErr, "timed out"},
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), "timed out"},
		{"cancelled", fmt.Errorf("x: %w", context.Canceled), "cancelled"},
		{"dns", &net.DNSError{Err: "no such host", Name: "broker.kguardian.svc"}, "name lookup failed"},
		{"json syntax", syn, "invalid response"},
		{"json type", typ, "invalid response"},
		{"other", errors.New("GET http://10.1.2.3:8080/x: EOF"), "request failed"},
	} {
		if tc.err == nil && tc.name != "nil" {
			t.Fatalf("%s: setup produced no error", tc.name)
		}
		if got := Of(tc.err); got != tc.want {
			t.Errorf("%s: Of(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}
