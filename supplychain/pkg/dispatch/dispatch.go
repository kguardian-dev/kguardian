// Package dispatch decouples sources from the broker client. Informer event
// handlers must not block on network I/O, so emissions go into a coalescing
// queue keyed by (kind, digest): if a digest changes twice before it is
// sent, only the latest payload is sent.
//
// Failures are handled per key, so one bad payload never holds up the
// others:
//   - a non-retryable failure (4xx other than 408/429, an oversized or
//     unencodable payload) is dropped, logged and counted;
//   - a retryable one (network, 5xx, 408, 429) waits out its own
//     exponential backoff with jitter while every other key keeps draining.
//
// A payload replaced while in flight or backing off is never retried over
// its replacement; the replacement starts with a clean backoff.
//
// Sends (including the enrichment step, e.g. a registry lookup) run on a
// small bounded worker pool, one key at a time, so a slow lookup or a slow
// broker call occupies one worker, not the whole queue.
package dispatch

import (
	"context"
	"math/rand/v2"
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

type item struct {
	e         trivy.Emission
	attempts  int
	notBefore time.Time
	// gen increments on every Enqueue for the key, so a failure can tell
	// whether it is still the current payload.
	gen uint64
}

// Enricher fills in image metadata (e.g. digest kind) before a send. It
// runs on a dispatcher worker, never in an informer handler, under
// EnrichTimeout.
type Enricher func(ctx context.Context, e *trivy.Emission)

// Dispatcher is a coalescing, per-key-backoff send queue in front of a
// broker.Client.
type Dispatcher struct {
	client  broker.Client
	log     *logrus.Logger
	metrics *metrics.Metrics

	// Enrich, when set, runs before each send, bounded by EnrichTimeout.
	Enrich Enricher
	// EnrichTimeout bounds one Enrich call. Default 5s.
	EnrichTimeout time.Duration
	// Workers is the number of concurrent sends. Default 3.
	Workers int
	// Backoff bounds for retryable failures.
	MinBackoff, MaxBackoff time.Duration
	// now and jitter are replaceable in tests.
	now    func() time.Time
	jitter func(time.Duration) time.Duration

	mu       sync.Mutex
	pending  map[key]*item
	inFlight map[key]bool
	gens     map[key]uint64
	notify   chan struct{}
}

// New returns a Dispatcher. m may be nil.
func New(client broker.Client, log *logrus.Logger, m *metrics.Metrics) *Dispatcher {
	return &Dispatcher{
		client:     client,
		log:        log,
		metrics:    m,
		MinBackoff: 5 * time.Second,
		MaxBackoff: 5 * time.Minute,
		now:        time.Now,
		// Full jitter in [d/2, d): spreads retries without ever retrying
		// sooner than half the nominal backoff.
		jitter: func(d time.Duration) time.Duration {
			if d <= 1 {
				return d
			}
			return d/2 + rand.N(d/2)
		},
		EnrichTimeout: 5 * time.Second,
		Workers:       3,
		pending:       map[key]*item{},
		inFlight:      map[key]bool{},
		gens:          map[key]uint64{},
		notify:        make(chan struct{}, 1),
	}
}

// Enqueue queues e, replacing any unsent payload for the same key (and its
// backoff). Never blocks.
func (d *Dispatcher) Enqueue(e trivy.Emission) {
	d.mu.Lock()
	k := key{e.Kind, e.Digest}
	d.gens[k]++
	d.pending[k] = &item{e: e, gen: d.gens[k]}
	d.setPendingLocked()
	d.mu.Unlock()
	d.wake()
}

func (d *Dispatcher) wake() {
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

// Pending returns the number of queued payloads (including ones backing off).
func (d *Dispatcher) Pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

type job struct {
	k  key
	it *item
}

// Run sends queued payloads until ctx is cancelled, then waits for the
// workers to finish their current send.
func (d *Dispatcher) Run(ctx context.Context) {
	workers := d.Workers
	if workers <= 0 {
		workers = 3
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-jobs:
					d.process(ctx, j)
				}
			}
		}()
	}
	defer wg.Wait()

	for {
		k, it, wait := d.nextDue()
		if it != nil {
			select {
			case jobs <- job{k, it}:
				continue
			case <-ctx.Done():
				return
			}
		}
		var t *time.Timer
		var timer <-chan time.Time
		if wait > 0 {
			t = time.NewTimer(wait)
			timer = t.C
		}
		select {
		case <-ctx.Done():
		case <-d.notify:
		case <-timer:
		}
		if t != nil {
			t.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (d *Dispatcher) process(ctx context.Context, j job) {
	if d.Enrich != nil {
		timeout := d.EnrichTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ectx, cancel := context.WithTimeout(ctx, timeout)
		d.Enrich(ectx, &j.it.e)
		cancel()
	}
	err := d.send(ctx, j.it.e)
	d.finish(j.k, j.it, err)
}

// nextDue pops the due item with the earliest notBefore, skipping keys
// already being sent. When none is due it returns the time until the
// soonest one.
func (d *Dispatcher) nextDue() (key, *item, time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var bestK key
	var best *item
	var soonest time.Duration
	for k, it := range d.pending {
		if d.inFlight[k] {
			continue // its replacement waits for the current send to finish
		}
		if it.notBefore.After(now) {
			if w := it.notBefore.Sub(now); soonest == 0 || w < soonest {
				soonest = w
			}
			continue
		}
		if best == nil || it.notBefore.Before(best.notBefore) {
			bestK, best = k, it
		}
	}
	if best == nil {
		return key{}, nil, soonest
	}
	delete(d.pending, bestK)
	d.inFlight[bestK] = true
	d.setPendingLocked()
	return bestK, best, 0
}

func (d *Dispatcher) finish(k key, it *item, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.inFlight, k)
	// A replacement may have been waiting on this key.
	defer d.wake()
	fields := logrus.Fields{"kind": it.e.Kind, "digest": it.e.Digest, "attempt": it.attempts + 1}
	switch {
	case err == nil:
		d.forgetLocked(k)
		return
	case !broker.Retryable(err):
		d.log.WithError(err).WithFields(fields).Error("broker rejected payload; dropping it (not retryable)")
		if d.metrics != nil {
			d.metrics.Dropped.WithLabelValues(string(it.e.Kind), broker.Reason(err)).Inc()
		}
		d.forgetLocked(k)
		return
	}
	if _, superseded := d.pending[k]; superseded || d.gens[k] != it.gen {
		return // a newer payload replaced it; that one is what gets sent
	}
	it.attempts++
	backoff := d.MinBackoff << min(it.attempts-1, 30)
	if backoff <= 0 || backoff > d.MaxBackoff {
		backoff = d.MaxBackoff
	}
	backoff = d.jitter(backoff)
	it.notBefore = d.now().Add(backoff)
	d.pending[k] = it
	d.setPendingLocked()
	d.log.WithError(err).WithFields(fields).WithField("retry_in", backoff.String()).
		Warn("broker submission failed; will retry")
}

// forgetLocked drops the generation counter once nothing is queued for k,
// so the map stays bounded by the digests currently in play.
func (d *Dispatcher) forgetLocked(k key) {
	if _, queued := d.pending[k]; !queued {
		delete(d.gens, k)
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
		switch {
		case err == nil:
		case broker.Retryable(err):
			result = "retry"
		default:
			result = "dropped"
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
