package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
)

func TestRunCommands(t *testing.T) {
	cases := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{nil, 2, "", "usage:"},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
		{[]string{"version"}, 0, "dev", ""},
		{[]string{"--help"}, 0, "node-sbom", ""},
		{[]string{"node-sbom"}, 1, "", "not yet implemented"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		code := run(c.args, &out, &errb)
		if code != c.code {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.code)
		}
		if c.stdout != "" && !strings.Contains(out.String(), c.stdout) {
			t.Errorf("%v: stdout %q", c.args, out.String())
		}
		if c.stderr != "" && !strings.Contains(errb.String(), c.stderr) {
			t.Errorf("%v: stderr %q", c.args, errb.String())
		}
	}
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8083" || !c.TrivyEnabled || c.BrokerIngest || !c.RegistryLookup ||
		c.TrivyResync != 10*time.Minute || c.TrivyRecheck != 5*time.Minute {
		t.Errorf("defaults: %+v", c)
	}
	// Ingest off by default: payloads are logged, never sent.
	cl, err := newBrokerClient(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cl.(broker.LoggingClient); !ok {
		t.Errorf("default client is %T", cl)
	}
}

func TestLoadConfigOverridesAndErrors(t *testing.T) {
	c, err := loadConfig(envMap(map[string]string{
		"LISTEN_ADDR":            " :9999 ",
		"TRIVY_OPERATOR_ENABLED": "false",
		"BROKER_INGEST_ENABLED":  "true",
		"BROKER_URL":             "http://broker:9090",
		"BROKER_AUTH_TOKEN":      " tok\n",
		"TRIVY_RESYNC_PERIOD":    "30s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":9999" || c.TrivyEnabled || !c.BrokerIngest || c.BrokerToken != "tok" || c.TrivyResync != 30*time.Second {
		t.Errorf("overrides: %+v", c)
	}
	cl, err := newBrokerClient(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cl.(*broker.HTTPClient); !ok {
		t.Errorf("ingest client is %T", cl)
	}

	for _, bad := range []map[string]string{
		{"TRIVY_OPERATOR_ENABLED": "maybe"},
		{"BROKER_INGEST_ENABLED": "yes please"},
		{"TRIVY_RESYNC_PERIOD": "0s"},
		{"TRIVY_RECHECK_PERIOD": "soon"},
		{"REGISTRY_LOOKUP_ENABLED": "sometimes"},
	} {
		if _, err := loadConfig(envMap(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
