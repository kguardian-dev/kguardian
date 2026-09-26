package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func TestAttestConfig(t *testing.T) {
	c, err := loadAttestConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.Interval != 10*time.Minute || c.Workers != 2 || c.SkipSCT || c.TrustedRootFile != "" || c.RegistryRPS != 5 {
		t.Errorf("defaults: %+v", c)
	}
	for _, bad := range []map[string]string{
		{"ATTESTATION_ENABLED": "on-ish"},
		{"ATTESTATION_INTERVAL": "10s"},
		{"ATTESTATION_WORKERS": "0"},
		{"ATTESTATION_WORKERS": "64"},
		{"ATTESTATION_SKIP_SCT": "maybe"},
		{"ATTESTATION_REGISTRY_RPS": "0"},
	} {
		if _, err := loadAttestConfig(envMap(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

// Discovery needs the broker: it refuses to start with ingest off.
func TestAttestRunnerNeedsIngest(t *testing.T) {
	ac := attestConfig{Enabled: true, Interval: time.Minute, Workers: 1, RegistryRPS: 1}
	_, err := newAttestRunner(ac, config{}, registry.Guard{}, prometheus.NewRegistry(), logrus.New())
	if err == nil || !strings.Contains(err.Error(), "BROKER_INGEST_ENABLED") {
		t.Fatalf("err = %v", err)
	}
	r, err := newAttestRunner(ac, config{BrokerIngest: true, BrokerURL: "http://broker:9090"}, registry.Guard{}, prometheus.NewRegistry(), logrus.New())
	if err != nil || r == nil {
		t.Fatalf("runner %v, err %v", r, err)
	}
}

func TestLoadKeys(t *testing.T) {
	if ks, err := loadKeys(""); err != nil || ks != nil {
		t.Fatalf("empty dir: %v %v", ks, err)
	}
	if ks, err := loadKeys(filepath.Join(t.TempDir(), "absent")); err != nil || ks != nil {
		t.Fatalf("absent dir: %v %v", ks, err)
	}
	dir := t.TempDir()
	pub, err := os.ReadFile("pkg/attest/testdata/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"release.pub": pub, "team-b.pem": pub, "README": []byte("x"), ".hidden.pub": []byte("x")} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ks, err := loadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 2 || ks[0].Name != "release" || ks[1].Name != "team-b" {
		t.Fatalf("keys = %+v", ks)
	}
}
