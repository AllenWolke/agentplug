package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type performanceCapture struct {
	items     []audit.PerformanceObservation
	err       error
	cancelled bool
}

func (p *performanceCapture) RecordPerformance(ctx context.Context, _ sharedkernel.Scope, o audit.PerformanceObservation) error {
	p.cancelled = ctx.Err() != nil
	p.items = append(p.items, o)
	return p.err
}

func TestPerformanceRecordingDoesNotLoseKnownModelResultOnCancelOrAuditFailure(t *testing.T) {
	p := &performanceCapture{err: errors.New("private database error")}
	m := &Module{performanceRecorder: p}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scope := scopeFromHarness(capabilityContext())
	started := time.Now()
	m.recordModelPerformance(ctx, scope, "private-request", "private-attempt", "model-version", true, started, started.Add(time.Millisecond), nil)
	if len(p.items) != 1 || p.cancelled || p.items[0].Status != "succeeded" || p.items[0].Operation != "embed" ||
		!strings.HasPrefix(p.items[0].UsageStepID, "model-step-") {
		t.Fatal("known measured result was erased", p)
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private provider error")} {
		m.recordModelPerformance(ctx, scope, "another-request", err.Error(), "model-version", false, started, started.Add(2*time.Millisecond), err)
	}
	if p.items[1].Status != "cancelled" || p.items[2].Status != "timeout" || p.items[3].Status != "failed" {
		t.Fatal("safe error statuses lost")
	}
}

func TestKnowledgePerformanceObservationsDoNotReplayPriorPhysicalRead(t *testing.T) {
	p := &performanceCapture{}
	m := &Module{performanceRecorder: p}
	scope := scopeFromHarness(capabilityContext())
	started := time.Now()
	for i := 0; i < 2; i++ {
		observer := m.knowledgePerformanceObserver(scope)
		observer(context.Background(), KnowledgeQueryObservation{StartedAt: started, FinishedAt: started.Add(time.Millisecond), CacheMode: "use", Lookups: 4, Hits: int64(i) * 4})
	}
	if len(p.items) != 2 || p.items[0].StepID == p.items[1].StepID || *p.items[0].CacheHits != 0 || *p.items[1].CacheHits != 4 {
		t.Fatal("physical query was collapsed or hits fabricated", p.items)
	}
	if (&Module{}).knowledgePerformanceObserver(scope) != nil {
		t.Fatal("standalone fixtures unexpectedly require audit")
	}
}
