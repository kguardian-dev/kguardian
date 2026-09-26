package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/attest"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/registry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// attestConfig is the signature-discovery configuration (#1533 P2-1).
// Off by default: when on, the component reads every running digest from
// the broker and contacts each image's registry and the Sigstore TUF CDN.
type attestConfig struct {
	Enabled bool
	// Interval between passes over the running digests.
	Interval time.Duration
	// Workers verifying digests concurrently.
	Workers int
	// TrustedRootFile is a trusted_root.json for a private Sigstore or an
	// air-gapped cluster; empty uses the public-good instance over TUF.
	TrustedRootFile string
	// TUFMirror overrides the TUF repository URL.
	TUFMirror string
	// SkipSCT drops the certificate-transparency requirement (private
	// Fulcio without a CT log).
	SkipSCT bool
	// KeysDir holds PEM public keys (*.pub, *.pem) for key-signed images;
	// each file's name without extension names the key.
	KeysDir     string
	RegistryRPS float64
}

func loadAttestConfig(getenv func(string) string) (attestConfig, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var c attestConfig
	var err error
	if c.Enabled, err = strconv.ParseBool(env("ATTESTATION_ENABLED", "false")); err != nil {
		return c, fmt.Errorf("ATTESTATION_ENABLED: %w", err)
	}
	if c.Interval, err = time.ParseDuration(env("ATTESTATION_INTERVAL", "10m")); err != nil || c.Interval < time.Minute {
		return c, fmt.Errorf("ATTESTATION_INTERVAL must be a duration of at least 1m")
	}
	if c.Workers, err = strconv.Atoi(env("ATTESTATION_WORKERS", "2")); err != nil || c.Workers < 1 || c.Workers > 16 {
		return c, fmt.Errorf("ATTESTATION_WORKERS must be 1..16")
	}
	if c.SkipSCT, err = strconv.ParseBool(env("ATTESTATION_SKIP_SCT", "false")); err != nil {
		return c, fmt.Errorf("ATTESTATION_SKIP_SCT: %w", err)
	}
	if c.RegistryRPS, err = strconv.ParseFloat(env("ATTESTATION_REGISTRY_RPS", "5"), 64); err != nil || c.RegistryRPS <= 0 || c.RegistryRPS > 100 {
		return c, fmt.Errorf("ATTESTATION_REGISTRY_RPS must be in (0, 100]")
	}
	c.TrustedRootFile = env("ATTESTATION_TRUSTED_ROOT_FILE", "")
	c.TUFMirror = env("ATTESTATION_TUF_MIRROR", "")
	c.KeysDir = env("ATTESTATION_KEYS_DIR", "")
	return c, nil
}

// loadKeys reads every *.pub / *.pem file in dir. A missing directory is
// no keys; an unreadable key file is an error.
func loadKeys(dir string) ([]attest.PublicKey, error) {
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ATTESTATION_KEYS_DIR: %w", err)
	}
	var out []attest.PublicKey
	for _, e := range ents {
		ext := filepath.Ext(e.Name())
		// ConfigMap mounts add ..data symlinks and dot-directories.
		if strings.HasPrefix(e.Name(), ".") || (ext != ".pub" && ext != ".pem") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("public key %s: %w", e.Name(), err)
		}
		out = append(out, attest.PublicKey{Name: strings.TrimSuffix(e.Name(), ext), PEM: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// attestMetrics are registered on the component's registry.
type attestMetrics struct {
	results *prometheus.CounterVec
	posts   *prometheus.CounterVec
	passes  *prometheus.CounterVec
	targets prometheus.Gauge
	passDur prometheus.Gauge
}

func newAttestMetrics(reg prometheus.Registerer) *attestMetrics {
	m := &attestMetrics{
		results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_attestation_results_total",
			Help: "Signature discovery results posted, by verdict and reason.",
		}, []string{"verdict", "reason"}),
		posts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_attestation_posts_total",
			Help: "Attestation results sent to the broker, by result (ok, retry, dropped).",
		}, []string{"result"}),
		passes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kguardian_supplychain_attestation_passes_total",
			Help: "Passes over the running digests, by result (ok, error).",
		}, []string{"result"}),
		targets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_attestation_targets",
			Help: "Running digests checked in the last pass.",
		}),
		passDur: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kguardian_supplychain_attestation_pass_seconds",
			Help: "Duration of the last pass.",
		}),
	}
	reg.MustRegister(m.results, m.posts, m.passes, m.targets, m.passDur)
	return m
}

// newAttestRunner builds the discovery runner. The broker client is
// required: the inventory comes from GET /images and results go to
// POST /images/{digest}/attestation.
func newAttestRunner(ac attestConfig, c config, guard registry.Guard, reg prometheus.Registerer, log *logrus.Logger) (*attest.Runner, error) {
	if !c.BrokerIngest {
		return nil, fmt.Errorf("ATTESTATION_ENABLED needs BROKER_INGEST_ENABLED=true: the running digests come from the broker and results go back to it")
	}
	keys, err := loadKeys(ac.KeysDir)
	if err != nil {
		return nil, err
	}
	var tr attest.TrustRoot
	if ac.TrustedRootFile != "" {
		tr = &attest.FileTrustRoot{Path: ac.TrustedRootFile}
	} else {
		tr = &attest.TUFTrustRoot{Transport: attest.RateLimit(guard.Transport(30*time.Second), 1, 4), MirrorURL: ac.TUFMirror}
	}
	v, err := attest.New(attest.Options{
		Guard:       guard,
		TrustRoot:   tr,
		SkipSCT:     ac.SkipSCT,
		TrustedKeys: keys,
		RegistryRPS: ac.RegistryRPS,
	})
	if err != nil {
		return nil, err
	}
	bc, err := attest.NewBrokerClient(c.BrokerURL, c.BrokerToken)
	if err != nil {
		return nil, err
	}
	m := newAttestMetrics(reg)
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.Name)
	}
	log.WithFields(logrus.Fields{
		"interval":    ac.Interval.String(),
		"trustRoot":   map[bool]string{true: "file", false: "public-good (TUF)"}[ac.TrustedRootFile != ""],
		"trustedKeys": names,
		"skipSCT":     ac.SkipSCT,
	}).Info("image signature discovery enabled")
	return &attest.Runner{
		Verifier:  v,
		Inventory: bc,
		Sink:      bc,
		Log:       log,
		Interval:  ac.Interval,
		Workers:   ac.Workers,
		OnResult:  func(verdict, reason string) { m.results.WithLabelValues(verdict, reason).Inc() },
		OnPost:    func(result string) { m.posts.WithLabelValues(result).Inc() },
		OnPass: func(n int, err error, took time.Duration) {
			res := "ok"
			if err != nil {
				res = "error"
			}
			m.passes.WithLabelValues(res).Inc()
			m.targets.Set(float64(n))
			m.passDur.Set(took.Seconds())
		},
	}, nil
}
