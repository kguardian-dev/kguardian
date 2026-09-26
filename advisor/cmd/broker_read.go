package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/advisor/pkg/k8s"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// Shared plumbing for the read-only broker views (profile, images): the
// broker port-forward every CLI command uses, and the -o json|yaml|table
// output convention (json passes the broker body through re-indented, so
// fields this CLI build does not know about still reach the operator).

// connectBroker opens the port-forward to the broker and returns the
// function that closes it. The broker token was resolved in PersistentPreRun.
func connectBroker(cmd *cobra.Command) (func(), error) {
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
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
