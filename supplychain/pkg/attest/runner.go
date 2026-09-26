package attest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Inventory lists the running image digests.
type Inventory interface {
	RunningImages(ctx context.Context) ([]Target, error)
}

// Sink receives results.
type Sink interface {
	Post(ctx context.Context, r Result) error
}

// Runner checks every running digest each Interval and posts each new
// result once. A result is re-posted only after the cache re-checks the
// digest (TTL), or when a post failed with a retryable error.
type Runner struct {
	Verifier  *Verifier
	Inventory Inventory
	Sink      Sink
	Log       *logrus.Logger
	// Interval between passes. Default 10m.
	Interval time.Duration
	// Workers verifying digests concurrently. Default 2.
	Workers int
	// Hooks for metrics; all optional.
	OnResult func(verdict, reason string)
	OnPost   func(result string) // ok | retry | dropped
	OnPass   func(targets int, err error, took time.Duration)

	mu     sync.Mutex
	posted map[string]time.Time // digest -> CheckedAt of the last result the broker accepted
	ready  bool
}

// Ready is true once a pass has completed (whatever its outcome).
func (r *Runner) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready
}

// Run passes until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	iv := r.Interval
	if iv <= 0 {
		iv = 10 * time.Minute
	}
	for {
		r.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}

// Pass runs one inventory pass.
func (r *Runner) Pass(ctx context.Context) {
	start := time.Now()
	targets, err := r.Inventory.RunningImages(ctx)
	if err != nil && !errors.Is(err, errInventoryTruncated) {
		r.log().WithError(err).Warn("attestation: could not read the image inventory; retrying next pass")
		r.finish(0, err, start)
		return
	}
	if err != nil {
		r.log().WithError(err).Warn("attestation: inventory truncated")
	}
	workers := r.Workers
	if workers <= 0 {
		workers = 2
	}
	ch := make(chan Target)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				r.one(ctx, t)
			}
		}()
	}
feed:
	for _, t := range targets {
		select {
		case ch <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()
	if err == nil && ctx.Err() == nil {
		// Forget digests that no longer run, so the map tracks the
		// inventory rather than everything ever seen.
		live := make(map[string]bool, len(targets))
		for _, t := range targets {
			live[t.Digest] = true
		}
		r.mu.Lock()
		for d := range r.posted {
			if !live[d] {
				delete(r.posted, d)
			}
		}
		r.mu.Unlock()
	}
	r.finish(len(targets), err, start)
}

func (r *Runner) finish(n int, err error, start time.Time) {
	r.mu.Lock()
	r.ready = true
	r.mu.Unlock()
	if r.OnPass != nil {
		r.OnPass(n, err, time.Since(start))
	}
}

func (r *Runner) one(ctx context.Context, t Target) {
	res := r.Verifier.Verify(ctx, t)
	r.mu.Lock()
	if r.posted == nil {
		r.posted = map[string]time.Time{}
	}
	last, seen := r.posted[t.Digest]
	r.mu.Unlock()
	if seen && last.Equal(res.CheckedAt) {
		return // this exact result is already stored
	}
	if r.OnResult != nil {
		r.OnResult(res.Verdict, res.Reason)
	}
	err := r.Sink.Post(ctx, res)
	outcome := "ok"
	switch {
	case err == nil:
	case Retryable(err):
		outcome = "retry"
		r.log().WithError(err).WithField("digest", t.Digest).Debug("attestation: post failed; retrying next pass")
	default:
		outcome = "dropped"
		r.log().WithError(err).WithField("digest", t.Digest).Warn("attestation: broker refused the result")
	}
	if outcome != "retry" {
		r.mu.Lock()
		r.posted[t.Digest] = res.CheckedAt
		r.mu.Unlock()
	}
	if r.OnPost != nil {
		r.OnPost(outcome)
	}
	if res.Verdict == VerdictInvalid {
		r.log().WithFields(logrus.Fields{"digest": t.Digest, "repository": t.Repository, "reason": res.Reason}).
			Warn("attestation: signature present but invalid")
	}
}

func (r *Runner) log() *logrus.Logger {
	if r.Log != nil {
		return r.Log
	}
	return logrus.StandardLogger()
}
