package capability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

func (m *Module) SetPerformanceRecorder(recorder audit.PerformanceRecorder) {
	m.performanceRecorder = recorder
}

func performanceStatus(err error) string {
	switch {
	case err == nil:
		return "succeeded"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return "failed"
	}
}

func (m *Module) recordPerformance(ctx context.Context, scope sharedkernel.Scope, o audit.PerformanceObservation) {
	if m.performanceRecorder == nil {
		return
	}
	// A telemetry failure must not erase a known billable result or trigger
	// another invocation. Missing observations remain unknown in evaluation.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := m.performanceRecorder.RecordPerformance(writeCtx, scope, o); err != nil {
		log.Printf("capability performance observation unavailable run_id=%q kind=%s", scope.RunID, o.Kind)
	}
}

func (m *Module) recordModelPerformance(ctx context.Context, scope sharedkernel.Scope, key, attempt, version string, embedding bool, started, finished time.Time, err error) *audit.PerformanceObservation {
	o := audit.NewPerformanceObservation(scope, key+"\x00"+attempt, "model_gateway", performanceStatus(err), started, finished)
	o.Operation, o.ModelVersionID = "generate", version
	linked := usagecost.StableModelUsageStepID(usagecost.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
		ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, RunID: scope.RunID}, key)
	if linked == nil {
		return nil
	}
	o.UsageStepID = *linked
	if embedding {
		o.Operation = "embed"
	}
	m.recordPerformance(ctx, scope, o)
	return &o
}

func (m *Module) knowledgePerformanceObserver(scope sharedkernel.Scope) func(context.Context, KnowledgeQueryObservation) {
	if m.performanceRecorder == nil {
		return nil
	}
	// Search is read-only and can execute again under a fresh HTTP attempt.
	// Distinct physical calls get distinct observation identities; cache hits
	// never replay a previous invocation's billing or timing as a new call.
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil
	}
	key := hex.EncodeToString(nonce[:])
	return func(ctx context.Context, measured KnowledgeQueryObservation) {
		o := audit.NewPerformanceObservation(scope, key, "knowledge_query", performanceStatus(measured.Err), measured.StartedAt, measured.FinishedAt)
		o.CacheMode = measured.CacheMode
		o.CacheLookups, o.CacheHits, o.CacheFailures = &measured.Lookups, &measured.Hits, &measured.Failures
		m.recordPerformance(ctx, scope, o)
	}
}
