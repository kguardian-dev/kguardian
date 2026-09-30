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
	if c.ListenAddr != ":8083" || !c.TrivyEnabled || c.BrokerIngest || c.RegistryLookup || c.RegistryAllowPrivate ||
		c.TrivyResync != 10*time.Minute || c.TrivyRecheck != 5*time.Minute || c.GrypeQuarantineTTL != time.Hour {
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
		"LISTEN_ADDR":                " :9999 ",
		"TRIVY_OPERATOR_ENABLED":     "false",
		"BROKER_INGEST_ENABLED":      "true",
		"BROKER_URL":                 "http://broker:9090",
		"BROKER_AUTH_TOKEN":          " tok\n",
		"TRIVY_RESYNC_PERIOD":        "30s",
		"GRYPE_ERROR_QUARANTINE_TTL": "30m",
		"GRYPE_SBOM_BUDGET_MIB":      "200",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":9999" || c.TrivyEnabled || !c.BrokerIngest || c.BrokerToken != "tok" || c.TrivyResync != 30*time.Second ||
		c.GrypeQuarantineTTL != 30*time.Minute || c.GrypeSBOMBudgetMiB != 200 {
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
		{"REGISTRY_ALLOW_PRIVATE": "lan"},
		{"GRYPE_ERROR_QUARANTINE_TTL": "1m"},
		{"GRYPE_ERROR_QUARANTINE_TTL": "a while"},
		{"GRYPE_SBOM_BUDGET_MIB": "8"},
		{"GRYPE_SBOM_BUDGET_MIB": "96Mi"},
	} {
		if _, err := loadConfig(envMap(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// The registry lookup follows broker ingest unless set explicitly.
func TestRegistryLookupIsOptIn(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"BROKER_INGEST_ENABLED": "true"}, false},
		{map[string]string{"BROKER_INGEST_ENABLED": "true", "REGISTRY_LOOKUP_ENABLED": "true"}, true},
		{map[string]string{"BROKER_INGEST_ENABLED": "true", "REGISTRY_LOOKUP_ENABLED": "false"}, false},
		{map[string]string{"REGISTRY_LOOKUP_ENABLED": "true"}, true},
	} {
		got, err := loadConfig(envMap(c.env))
		if err != nil {
			t.Fatal(err)
		}
		if got.RegistryLookup != c.want {
			t.Errorf("%v: RegistryLookup = %v, want %v", c.env, got.RegistryLookup, c.want)
		}
	}
}

func TestRegistrySBOMIsOptIn(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"BROKER_INGEST_ENABLED": "true"}, false},
		{map[string]string{"BROKER_INGEST_ENABLED": "true", "REGISTRY_SBOM_ENABLED": "true"}, true},
		{map[string]string{"REGISTRY_SBOM_ENABLED": "false"}, false},
	} {
		got, err := loadConfig(envMap(c.env))
		if err != nil {
			t.Fatal(err)
		}
		if got.RegistrySBOM != c.want || got.RegistrySBOMInterval != 15*time.Minute {
			t.Errorf("%v: %+v", c.env, got)
		}
	}
	if _, err := loadConfig(envMap(map[string]string{"REGISTRY_SBOM_INTERVAL": "0s"})); err == nil {
		t.Error("zero interval accepted")
	}
}

func TestNodeSBOMIsOptIn(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"BROKER_INGEST_ENABLED": "true", "GRYPE_MATCHER_URL": "http://127.0.0.1:8090"}, false},
		{map[string]string{"NODE_SBOM_ENABLED": "true"}, true},
		{map[string]string{"NODE_SBOM_ENABLED": "false"}, false},
	} {
		got, err := loadConfig(envMap(c.env))
		if err != nil {
			t.Fatal(err)
		}
		if got.NodeSBOM != c.want || got.NodeSBOMInterval != 5*time.Minute {
			t.Errorf("%v: %+v", c.env, got)
		}
	}
	for _, bad := range []map[string]string{
		{"NODE_SBOM_ENABLED": "on"},
		{"NODE_SBOM_INTERVAL": "0s"},
		{"NODE_SBOM_INTERVAL": "often"},
		{"GRYPE_NODE_GROUP_MAX_WAIT": "30s"},
		{"GRYPE_NODE_GROUP_MAX_WAIT": "later"},
	} {
		if _, err := loadConfig(envMap(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	c, err := loadConfig(envMap(map[string]string{"NODE_SBOM_INTERVAL": "90s"}))
	if err != nil || c.NodeSBOMInterval != 90*time.Second {
		t.Errorf("interval: %v %v", c.NodeSBOMInterval, err)
	}
	if c.GrypeNodeGroupMaxWait != 30*time.Minute {
		t.Errorf("node group max wait default %v", c.GrypeNodeGroupMaxWait)
	}
}
