package compensation

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// A Port owns only its registered effect type/version. InspectOriginal must
// prove absence plus fencing of late forward writes. Lookup must be read-only.
// Compensate must be idempotent for Step.CompensationKey and reject late writes.
type Port interface {
	Lookup(context.Context, Step) (Receipt, bool, error)
	InspectOriginal(context.Context, Step) (OriginalEffect, error)
	Compensate(context.Context, Step) (Receipt, error)
}

type Registration struct {
	Provider string
	Version  string
	Timeout  time.Duration
	Port     Port
}

type Resolution struct {
	Receipt      *Receipt
	Code         string
	RetryAt      time.Time
	NotSubmitted bool
}

type Queue interface {
	Claim(context.Context, sharedkernel.Scope, string, time.Duration) (Lease, bool, error)
	MarkSubmitted(context.Context, Lease) error
	Resolve(context.Context, Lease, Resolution) error
}

type Engine struct {
	queue Queue
	owner string
	ports map[string]Registration
}

type leaseContextKey struct{}

// LeaseFromContext is available only to the registered adapter invoked by
// Engine. No HTTP body may supply a control lease. Local adapters pass it to
// GuardLeaseTx when committing the inverse operation and its receipt.
func LeaseFromContext(ctx context.Context, step Step) (Lease, error) {
	if ctx == nil {
		return Lease{}, ErrInvalid
	}
	l, ok := ctx.Value(leaseContextKey{}).(Lease)
	if !ok || validateLease(l) != nil || l.Step.Digest() != step.Digest() {
		return Lease{}, ErrInvalid
	}
	return l, nil
}

// CurrentLeaseFromContext is for a registered control adapter sharing the
// inverse transaction. The context key is private and cannot be supplied by
// an HTTP request. Adapters must still GuardLeaseTx before any commit.
func CurrentLeaseFromContext(ctx context.Context) (Lease, error) {
	if ctx == nil {
		return Lease{}, ErrInvalid
	}
	l, ok := ctx.Value(leaseContextKey{}).(Lease)
	if !ok || validateLease(l) != nil {
		return Lease{}, ErrInvalid
	}
	return l, nil
}

func NewEngine(queue Queue, owner string, registrations ...Registration) (*Engine, error) {
	if queue == nil || !token(owner, 64) || len(registrations) > 128 {
		return nil, ErrInvalid
	}
	e := &Engine{queue: queue, owner: owner, ports: make(map[string]Registration)}
	for _, r := range registrations {
		key := r.Provider + "\x00" + r.Version
		if !token(r.Provider, 128) || !token(r.Version, 128) || r.Port == nil || r.Timeout < time.Second || r.Timeout > time.Minute {
			return nil, ErrInvalid
		}
		if _, ok := e.ports[key]; ok {
			return nil, ErrConflict
		}
		e.ports[key] = r
	}
	return e, nil
}

// Tick handles at most one inverse operation. Hosts run a fixed worker pool;
// this method never spawns an unbounded goroutine or retries a forward Tool.
func (e *Engine) Tick(ctx context.Context, scope sharedkernel.Scope) (bool, error) {
	if ctx == nil || scope.ValidateTrusted() != nil {
		return false, ErrInvalid
	}
	l, found, err := e.queue.Claim(ctx, scope, e.owner, 90*time.Second)
	if err != nil || !found {
		return found, err
	}
	if l.Step.Validate() != nil || l.CancellationScope() != scope {
		return true, ErrInvalid
	}
	r, ok := e.ports[l.Step.Provider+"\x00"+l.Step.ProviderVersion]
	if !ok {
		return true, e.pending(ctx, l, "COMPENSATOR_UNAVAILABLE", false)
	}
	callCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	callCtx = context.WithValue(callCtx, leaseContextKey{}, l)
	receipt, confirmed, err := r.Port.Lookup(callCtx, l.Step)
	if err != nil {
		return true, e.pending(ctx, l, "COMPENSATION_RECEIPT_UNCONFIRMED", false)
	}
	if confirmed {
		return true, e.complete(ctx, l, receipt)
	}
	original, err := r.Port.InspectOriginal(callCtx, l.Step)
	if err != nil || original.Validate(l.Step) != nil || original.State == "unknown" {
		return true, e.pending(ctx, l, "ORIGINAL_EFFECT_UNCONFIRMED", false)
	}
	if original.State == "no_effect" {
		receipt = Receipt{Version: ContractVersion, StepDigest: l.Step.Digest(), Key: l.Step.CompensationKey(), Action: "no_effect", EvidenceDigest: original.EvidenceDigest}
		return true, e.complete(ctx, l, receipt)
	}
	// After submission or a crash in that window, only query receipts. A
	// timeout must not cause a duplicate external correction/undo request.
	if l.Submitted {
		return true, e.pending(ctx, l, "COMPENSATION_RESULT_UNKNOWN", false)
	}
	if l.Invocations >= 5 {
		return true, e.pending(ctx, l, "COMPENSATION_RETRY_BUDGET_EXHAUSTED", false)
	}
	if err := e.queue.MarkSubmitted(ctx, l); err != nil {
		return true, err
	}
	receipt, err = r.Port.Compensate(callCtx, l.Step)
	if err != nil {
		if errors.Is(err, ErrNotSubmitted) {
			return true, e.pending(ctx, l, "COMPENSATION_NOT_SUBMITTED", true)
		}
		return true, e.pending(ctx, l, "COMPENSATION_RESULT_UNKNOWN", false)
	}
	return true, e.complete(ctx, l, receipt)
}

func (e *Engine) complete(ctx context.Context, l Lease, r Receipt) error {
	if r.Validate(l.Step) != nil {
		return e.pending(ctx, l, "COMPENSATION_RECEIPT_INVALID", false)
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return e.queue.Resolve(writeCtx, l, Resolution{Receipt: &r})
}

func (e *Engine) pending(ctx context.Context, l Lease, code string, notSubmitted bool) error {
	delay := 30 * time.Second
	if notSubmitted {
		delay = time.Second << min(l.Attempts, 5)
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return e.queue.Resolve(writeCtx, l, Resolution{Code: code, RetryAt: time.Now().UTC().Add(delay), NotSubmitted: notSubmitted})
}
