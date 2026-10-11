package compensation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type engineQueue struct {
	lease           Lease
	marked          int
	result          Resolution
	failSubmission  bool
	resolved        bool
	requireDetached bool
}

func (q *engineQueue) Claim(context.Context, sharedkernel.Scope, string, time.Duration) (Lease, bool, error) {
	return q.lease, true, nil
}
func (q *engineQueue) MarkSubmitted(ctx context.Context, _ Lease) error {
	if q.failSubmission {
		return ErrLeaseLost
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	q.marked++
	return nil
}
func (q *engineQueue) Resolve(ctx context.Context, _ Lease, r Resolution) error {
	if q.requireDetached && ctx.Err() != nil {
		return errors.New("result write reused the cancelled call context")
	}
	q.result = r
	q.resolved = true
	return nil
}

type enginePort struct {
	lookup           Receipt
	found            bool
	lookupErr        error
	original         OriginalEffect
	inspectErr       error
	result           Receipt
	callErr          error
	lookups          int
	inspections      int
	calls            int
	cancelDuringCall context.CancelFunc
}

func (p *enginePort) Lookup(context.Context, Step) (Receipt, bool, error) {
	p.lookups++
	return p.lookup, p.found, p.lookupErr
}
func (p *enginePort) InspectOriginal(context.Context, Step) (OriginalEffect, error) {
	p.inspections++
	return p.original, p.inspectErr
}
func (p *enginePort) Compensate(ctx context.Context, s Step) (Receipt, error) {
	p.calls++
	if _, err := LeaseFromContext(ctx, s); err != nil {
		return Receipt{}, err
	}
	if p.cancelDuringCall != nil {
		p.cancelDuringCall()
	}
	return p.result, p.callErr
}
func engineFixture(t *testing.T) (*Engine, *engineQueue, *enginePort) {
	t.Helper()
	s := testStep()
	q := &engineQueue{lease: Lease{Step: s, Owner: "worker", Token: "01234567890123456789012345678901", Fence: 1, Until: time.Now().Add(time.Minute), Attempts: 1}}
	p := &enginePort{original: OriginalEffect{StepDigest: s.Digest(), State: "applied", EvidenceDigest: hash("original effect")}, result: testReceipt(s, "rolled_back")}
	e, err := NewEngine(q, "worker", Registration{Provider: s.Provider, Version: s.ProviderVersion, Timeout: time.Second, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	return e, q, p
}

func TestEngineCompensatesOnlyKnownAppliedRegisteredEffect(t *testing.T) {
	e, q, p := engineFixture(t)
	if found, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil || !found {
		t.Fatal(found, err)
	}
	if q.marked != 1 || p.calls != 1 || q.result.Receipt == nil || q.result.Receipt.Action != "rolled_back" {
		t.Fatal("inverse operation or completion evidence missing")
	}
}

func TestEngineNeverReplaysSubmittedUnknownInverse(t *testing.T) {
	e, q, p := engineFixture(t)
	q.lease.Submitted = true
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 || q.marked != 0 || q.result.Code != "COMPENSATION_RESULT_UNKNOWN" || q.result.Receipt != nil {
		t.Fatal("unknown inverse was replayed or fabricated as complete")
	}
}

func TestEngineRestoresReceiptWithoutExecutingAgain(t *testing.T) {
	e, q, p := engineFixture(t)
	q.lease.Submitted = true
	p.found = true
	p.lookup = p.result
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 || p.inspections != 0 || q.result.Receipt == nil {
		t.Fatal("durable inverse receipt did not short circuit execution")
	}
}

func TestEngineDoesNotInventBusinessEffectFromMissingReceipt(t *testing.T) {
	for _, unknown := range []OriginalEffect{{StepDigest: testStep().Digest(), State: "unknown"}, {}, {StepDigest: hash("other"), State: "applied", EvidenceDigest: hash("evidence")}} {
		e, q, p := engineFixture(t)
		p.original = unknown
		if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
			t.Fatal(err)
		}
		if p.calls != 0 || q.result.Code != "ORIGINAL_EFFECT_UNCONFIRMED" || q.result.Receipt != nil {
			t.Fatal("unknown original effect triggered compensation")
		}
	}
}

func TestEngineAcceptsProvenNoEffectWithoutUndo(t *testing.T) {
	e, q, p := engineFixture(t)
	p.original.State = "no_effect"
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 || q.marked != 0 || q.result.Receipt == nil || q.result.Receipt.Action != "no_effect" {
		t.Fatal("proven no-effect was not recorded")
	}
}

func TestEngineInvalidReceiptCannotBecomeCompletion(t *testing.T) {
	for _, fromLookup := range []bool{false, true} {
		e, q, p := engineFixture(t)
		bad := p.result
		bad.Key = hash("different operation")
		if fromLookup {
			p.found = true
			p.lookup = bad
		} else {
			p.result = bad
		}
		if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
			t.Fatal(err)
		}
		if q.result.Receipt != nil || q.result.Code != "COMPENSATION_RECEIPT_INVALID" {
			t.Fatal("unbound receipt became complete")
		}
	}
}

func TestEngineRetriesOnlyProvenNotSubmittedErrors(t *testing.T) {
	for _, proven := range []bool{false, true} {
		e, q, p := engineFixture(t)
		p.callErr = context.DeadlineExceeded
		if proven {
			p.callErr = errors.Join(ErrNotSubmitted, errors.New("adapter rejected before dispatch"))
		}
		if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
			t.Fatal(err)
		}
		if q.result.NotSubmitted != proven || q.result.Receipt != nil || q.result.RetryAt.IsZero() {
			t.Fatal("submission classification was lost")
		}
	}
}

func TestEngineRetryBudgetDoesNotInvokeSixthInverse(t *testing.T) {
	e, q, p := engineFixture(t)
	q.lease.Invocations = 5
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 || q.marked != 0 || q.result.Code != "COMPENSATION_RETRY_BUDGET_EXHAUSTED" {
		t.Fatal("retry limit exceeded")
	}
}

func TestEngineRefusesStaleLeaseBeforeExternalOperation(t *testing.T) {
	e, q, p := engineFixture(t)
	q.failSubmission = true
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
	if p.calls != 0 {
		t.Fatal("inverse called after lease was lost")
	}
}

func TestEnginePersistsUnknownAfterControlContextCancellation(t *testing.T) {
	e, q, p := engineFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.cancelDuringCall = cancel
	p.callErr = context.Canceled
	q.requireDetached = true
	if _, err := e.Tick(ctx, q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if !q.resolved || q.result.Code != "COMPENSATION_RESULT_UNKNOWN" {
		t.Fatal("cancelled HTTP context discarded inverse uncertainty")
	}
}

func TestEnginePinnedProviderVersionAndMissingHandlerFailClosed(t *testing.T) {
	e, q, p := engineFixture(t)
	q.lease.Step.ProviderVersion = "unregistered"
	if _, err := e.Tick(context.Background(), q.lease.Step.Root); err != nil {
		t.Fatal(err)
	}
	if p.calls != 0 || p.lookups != 0 || q.result.Code != "COMPENSATOR_UNAVAILABLE" {
		t.Fatal("missing version fell back to another inverse provider")
	}
}
