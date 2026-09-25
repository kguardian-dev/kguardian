// Package dispatch decouples sources from the broker client. Informer event
// handlers must not block on network I/O, so emissions go into a coalescing
// queue keyed by (kind, digest): if a digest changes twice before it is
// sent, only the latest payload is sent. A failed send is retried with
// backoff unless a newer payload for the same key has arrived meanwhile.
package dispatch

import (
	"context"
	"sync"
	"time"

	"github.com/kguardian-dev/kguardian/supplychain/pkg/broker"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/metrics"
	"github.com/kguardian-dev/kguardian/supplychain/pkg/trivy"
	"github.com/sirupsen/logrus"
)

type key struct {
	kind   trivy.Kind
	digest string
}

// Dispatcher is a coalescing send queue in front of a broker.Client.
type Dispatcher struct {
	client  broker.Client
	log     *logrus.Logger
	metrics *metrics.Metrics

	// Backoff bounds for failed sends.
	MinBackoff, MaxBackoff time.Duration

	mu      sync.Mutex
	pending map[key]trivy.Emission
	order   []key
	notify  chan struct{}
}

// New returns a Dispatcher. m may be nil.
func New(client broker.Client, log *logrus.Logger, m *metrics.Metrics) *Dispatcher {
	return &Dispatcher{
		client:     client,
		log:        log,
		metrics:    m,
		MinBackoff: 5 * time.Second,
		MaxBackoff: 5 * time.Minute,
		pending:    map[key]trivy.Emission{},
		notify:     make(chan struct{}, 1),
	}
}

// Enqueue queues e, replacing any unsent payload for the same key. Never
// blocks.
func (d *Dispatcher) Enqueue(e trivy.Emission) {
	d.mu.Lock()
	k := key{e.Kind, e.Digest}
	if _, ok := d.pending[k]; !ok {
		d.order = append(d.order, k)
	}
	d.pending[k] = e
	d.setPendingLocked()
	d.mu.Unlock()
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

// Pending returns the number of queued payloads.
func (d *Dispatcher) Pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

// Run sends queued payloads until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-d.notify:
			}
		}
		if d.drain(ctx) {
			backoff = 0
			continue
		}
		// A send failed: retry the remainder after a backoff.
		if backoff == 0 {
			backoff = d.MinBackoff
		} else if backoff *= 2; backoff > d.MaxBackoff {
			backoff = d.MaxBackoff
		}
	}
}

// drain sends everything queued, in arrival order. It returns false as soon
// as one send fails; the failed payload is put back unless it has already
// been superseded.
func (d *Dispatcher) drain(ctx context.Context) bool {
	for {
		d.mu.Lock()
		if len(d.order) == 0 {
			d.mu.Unlock()
			return true
		}
		k := d.order[0]
		d.order = d.order[1:]
		e := d.pending[k]
		delete(d.pending, k)
		d.setPendingLocked()
		d.mu.Unlock()

		if err := d.send(ctx, e); err != nil {
			d.log.WithError(err).WithFields(logrus.Fields{"kind": e.Kind, "digest": e.Digest}).
				Warn("broker submission failed; will retry")
			d.mu.Lock()
			if _, superseded := d.pending[k]; !superseded {
				d.pending[k] = e
				d.order = append([]key{k}, d.order...)
				d.setPendingLocked()
			}
			d.mu.Unlock()
			return false
		}
	}
}

func (d *Dispatcher) send(ctx context.Context, e trivy.Emission) error {
	var err error
	switch e.Kind {
	case trivy.KindVulnerabilities:
		err = d.client.SubmitVulnerabilities(ctx, e.Vulns)
	case trivy.KindSBOM:
		err = d.client.SubmitSBOM(ctx, e.SBOM)
	}
	if d.metrics != nil {
		result := "ok"
		if err != nil {
			result = "error"
		}
		d.metrics.Emissions.WithLabelValues(string(e.Kind), result).Inc()
	}
	return err
}

func (d *Dispatcher) setPendingLocked() {
	if d.metrics != nil {
		d.metrics.PendingEmissions.Set(float64(len(d.pending)))
	}
}
