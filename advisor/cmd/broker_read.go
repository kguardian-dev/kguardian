package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/kguardian-dev/kguardian/advisor/pkg/api"
	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// Shared plumbing for the read-only broker views (profile, images): the
// broker port-forward every CLI command uses, and the -o json|yaml|table
// output convention (json passes the broker body through re-indented, so
// fields this CLI build does not know about still reach the operator).

// brokerURLEnv names a broker base URL to use directly instead of a
// port-forward: an Ingress, a port-forward you run yourself, or a broker on
// this machine.
const brokerURLEnv = "KGUARDIAN_BROKER_URL"

// directBrokerURL validates the KGUARDIAN_BROKER_URL value: an http(s) URL
// with a host and nothing after the path. "" = not set.
func directBrokerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s must be an http(s) URL such as http://127.0.0.1:9090, got %q", brokerURLEnv, raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// plainHTTPTokenWarning is the warning for sending the broker token in
// clear text: an http:// URL whose host is not loopback. "" = no warning.
func plainHTTPTokenWarning(direct, token string) string {
	u, err := url.Parse(direct)
	if err != nil || u.Scheme != "http" || strings.TrimSpace(token) == "" {
		return ""
	}
	host := u.Hostname()
	if host == "localhost" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("%s is plain http to %s: the broker token is sent unencrypted; use https or a port-forward", brokerURLEnv, host)
}

// connectBroker opens the port-forward to the broker and returns the
// function that closes it; with KGUARDIAN_BROKER_URL set it uses that URL
// and opens nothing. The broker token was resolved in PersistentPreRun.
func connectBroker(cmd *cobra.Command) (func(), error) {
	direct, err := directBrokerURL(os.Getenv(brokerURLEnv))
	if err != nil {
		return nil, err
	}
	if direct != "" {
		log.Debug().Msgf("Using the broker at %s (%s)", direct, brokerURLEnv)
		if w := plainHTTPTokenWarning(direct, api.BrokerAuthToken); w != "" {
			log.Warn().Msg(w)
		}
		api.BrokerBaseURL = direct
		return func() {}, nil
	}
	config, ok := cmd.Context().Value(k8s.ConfigKey).(*k8s.Config)
	if !ok || config == nil {
		return nil, fmt.Errorf("failed to retrieve Kubernetes configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stopChan, errChan, done := k8s.PortForward(config, brokerNamespace, brokerService)
	select {
	case <-done:
		log.Debug().Msg("Port forwarding setup completed")
		return func() { close(stopChan) }, nil
	case err := <-errChan:
		close(stopChan)
		return nil, fmt.Errorf("setting up broker port-forward: %w", err)
	case <-ctx.Done():
		close(stopChan)
		return nil, fmt.Errorf("timeout waiting for broker port-forward")
	}
}

// brokerReadErr wraps a broker read failure. A 401/403 gets the token hint:
// these endpoints need a token carrying the broker's read scope.
func brokerReadErr(what string, err error) error {
	var ae *api.BrokerAuthError
	if errors.As(err, &ae) {
		return fmt.Errorf("%s: %w\nhint: this needs a broker token with the read scope (the \"read\" key of the broker auth Secret, e.g. kubectl -n kguardian get secret kguardian-broker-auth -o jsonpath='{.data.read}' | base64 -d > token); pass it with --broker-token-file token or set KGUARDIAN_BROKER_TOKEN", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// parseOutput normalises -o and checks it against the allowed formats.
func parseOutput(raw string, allowed ...string) (string, error) {
	o := strings.ToLower(strings.TrimSpace(raw))
	for _, a := range allowed {
		if o == a {
			return o, nil
		}
	}
	return "", fmt.Errorf("invalid --output %q: must be one of %s", raw, strings.Join(allowed, ", "))
}

// writeRaw emits a broker JSON body as indented JSON or as YAML.
func writeRaw(w io.Writer, raw []byte, format string) error {
	switch format {
	case "json":
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			buf.Reset()
			buf.Write(raw)
		}
		buf.WriteByte('\n')
		_, err := w.Write(buf.Bytes())
		return err
	case "yaml":
		out, err := yaml.JSONToYAML(raw)
		if err != nil {
			return fmt.Errorf("converting broker response to YAML: %w", err)
		}
		_, err = w.Write(out)
		return err
	default:
		return fmt.Errorf("writeRaw: unsupported format %q", format)
	}
}

// orDash renders an optional string, "-" when unknown or empty.
func orDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

// shortDigest trims a digest to algorithm plus 12 hex characters for tables.
func shortDigest(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

// cell makes free text safe for a tabwriter column.
func cell(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return ' '
		// Other control characters and invisible format characters (bidi
		// overrides, zero-width marks, line separators) in cluster data
		// never reach the terminal.
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
			return '?'
		}
		return r
	}, s)
}
