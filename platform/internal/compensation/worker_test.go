package compensation

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// A finite durable-queue stand-in: an unresolved submitted attempt stays in
// the root but cannot be claimed again until its persisted retry deadline.
type workerFixture struct {
	engineQueue
	port            *enginePort
	remaining, next int
	blocked         bool
	listErr         error
}

func (q *workerFixture) ListPending(context.Context, int) ([]sharedkernel.Scope, error) {
	if q.listErr != nil {
		return nil, q.listErr
	}
	if q.remaining == 0 {
		return nil, nil
	}
	return []sharedkernel.Scope{testScope()}, nil
}
func (q *workerFixture) TryFinalize(context.Context, sharedkernel.Scope) error {
	if q.remaining != 0 {
		return ErrPending
	}
	return nil
}
func (q *workerFixture) Claim(context.Context, sharedkernel.Scope, string, time.Duration) (Lease, bool, error) {
	if q.blocked || q.remaining == 0 {
		return Lease{}, false, nil
	}
	s := testStep()
	s.CallID = fmt.Sprintf("call-%d", q.next)
	s.ID = StepID(s.Scope, s.Kind, s.CallID)
	q.lease.Step = s
	q.port.original = OriginalEffect{StepDigest: s.Digest(), State: "applied", EvidenceDigest: hash("known original")}
	q.port.result = testReceipt(s, "rolled_back")
	return q.lease, true, nil
}
func (q *workerFixture) Resolve(ctx context.Context, l Lease, r Resolution) error {
	if err := q.engineQueue.Resolve(ctx, l, r); err != nil {
		return err
	}
	if r.Receipt == nil {
		q.blocked = true
	} else {
		q.remaining--
		q.next++
	}
	return nil
}
func newWorkerFixture(t *testing.T, n int) (*Engine, *workerFixture) {
	t.Helper()
	_, base, p := engineFixture(t)
	q := &workerFixture{engineQueue: *base, port: p, remaining: n}
	e, err := NewEngine(q, "worker", Registration{Provider: "example", Version: "v1", Timeout: time.Second, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	return e, q
}

func TestWorkerDrainsKnownBacklogAndYieldsWithoutIdlePerInverse(t *testing.T) {
	e, q := newWorkerFixture(t, 20)
	var delays []time.Duration
	err := e.run(context.Background(), q, 5*time.Second, nil, func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		if d == 5*time.Second {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || q.port.calls != 20 || q.marked != 20 || q.remaining != 0 || len(delays) != 2 || delays[0] != 10*time.Millisecond || delays[1] != 5*time.Second {
		t.Fatalf("backlog failed to drain/yield: calls=%d remaining=%d delays=%v err=%v", q.port.calls, q.remaining, delays, err)
	}
}

func TestWorkerUnknownAttemptBacksOffWithoutResending(t *testing.T) {
	e, q := newWorkerFixture(t, 1)
	q.lease.Submitted = true
	sweeps := 0
	err := e.run(context.Background(), q, 5*time.Second, func(SweepStats, bool) { sweeps++ }, func(_ context.Context, d time.Duration) error {
		if d != 5*time.Second {
			t.Fatal("unknown attempt skipped its backoff", d)
		}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) || sweeps != 2 || q.port.calls != 0 || q.marked != 0 || !q.blocked || q.remaining != 1 {
		t.Fatal("unknown was resent, finalized or spun", sweeps, q.port.calls, err)
	}
}

func TestWorkerIdleAndStoreErrorUsePollingInterval(t *testing.T) {
	for _, storeErr := range []error{nil, errors.New("unavailable")} {
		e, q := newWorkerFixture(t, 0)
		q.listErr = storeErr
		waits := 0
		observedError := false
		err := e.run(context.Background(), q, 5*time.Second, func(_ SweepStats, failed bool) { observedError = failed }, func(_ context.Context, d time.Duration) error {
			waits++
			if d != 5*time.Second {
				t.Fatal(d)
			}
			return context.Canceled
		})
		if !errors.Is(err, context.Canceled) || waits != 1 || observedError != (storeErr != nil) {
			t.Fatal("idle/error spun", waits, observedError, err)
		}
	}
}

func TestWorkerCancellationPreventsNextAdmission(t *testing.T) {
	e, q := newWorkerFixture(t, 20)
	ctx, cancel := context.WithCancel(context.Background())
	err := e.run(ctx, q, 5*time.Second, func(stats SweepStats, _ bool) {
		if stats.Handled == 1 {
			cancel()
		}
	}, waitWorker)
	if !errors.Is(err, context.Canceled) || q.port.calls != 1 || q.remaining != 19 {
		t.Fatal("cancellation admitted more work", q.port.calls, err)
	}
}
