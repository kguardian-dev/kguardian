// Package brokercause turns an error from reading the broker into a
// coarse, user-safe cause for status messages and conditions: fixed words
// and a status number only, never a URL, host, port, query, or the HTTP
// client's or the broker's error text. Callers log the full error.
//
// Both broker readers in the evaluator (imagetrust's running-container
// feed and appprofile's profile client) use Of, so status has one closed
// set of causes.
package brokercause

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

// StatusCoder is a non-2xx broker answer.
type StatusCoder interface {
	HTTPStatus() int
}

// ErrTooLarge: a broker response exceeded the reader's size limit.
var ErrTooLarge = errors.New("broker response too large")

// Of returns the cause of err, one of: "status N", "response too large",
// "TLS verification failed", "timed out", "cancelled", "name lookup
// failed", "connection failed", "invalid response", "request failed".
func Of(err error) string {
	var sc StatusCoder
	var cert *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var ne net.Error
	var dns *net.DNSError
	var op *net.OpError
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "no error"
	case errors.As(err, &sc):
		return fmt.Sprintf("status %d", sc.HTTPStatus())
	case errors.Is(err, ErrTooLarge):
		return "response too large"
	case errors.As(err, &cert), errors.As(err, &unknownCA), errors.As(err, &host), errors.As(err, &invalid):
		return "TLS verification failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &dns):
		return "name lookup failed"
	case errors.As(err, &op) && op.Op == "dial":
		return "connection failed"
	case errors.As(err, &syn), errors.As(err, &typ):
		return "invalid response"
	default:
		return "request failed"
	}
}
