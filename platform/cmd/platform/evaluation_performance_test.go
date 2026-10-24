package main

import (
	"strings"
	"testing"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func evaluationPerformanceModel(status string) audit.PerformanceObservation {
	start := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	o := audit.NewPerformanceObservation(sharedkernel.Scope{RunID: "run"}, status, "model_gateway", status, start, start.Add(21*time.Millisecond))
	o.UsageStepID = "model-step-" + strings.Repeat("a", 64)
	o.ModelVersionID, o.Operation = "published-model", "generate"
	return o
}

func TestEvaluationPerformanceEvidenceRequiresExactUsageLinks(t *testing.T) {
	for _, name := range []string{"matched", "missing", "unrelated-failure", "duplicate-success", "legacy-unlinked", "truncated", "failed-then-success"} {
		t.Run(name, func(t *testing.T) {
			model := evaluationPerformanceModel("succeeded")
			items := []audit.PerformanceObservation{model}
			complete, linked := true, true
			switch name {
			case "missing":
				items = nil
			case "unrelated-failure":
				items[0].Status = "failed"
			case "duplicate-success":
				items = append(items, model)
			case "legacy-unlinked":
				linked = false
			case "truncated":
				complete = false
			case "failed-then-success":
				items = append([]audit.PerformanceObservation{evaluationPerformanceModel("failed")}, model)
			}
			trajectory := agenteval.Trajectory{RunID: "run", FinishedAt: "2026-10-13T00:00:01Z", Complete: true}
			appendPerformanceEvidence(&trajectory, items, complete, []string{model.UsageStepID}, linked, false)
			want := name == "matched" || name == "failed-then-success"
			if trajectory.Coverage["model_timing"] != want {
				t.Fatal("unlinked/model replay became measured completeness", trajectory.Coverage)
			}
			if trajectory.Measurements.CacheHits != nil || trajectory.Measurements.CacheLookups != nil {
				t.Fatal("missing cache became zero")
			}
		})
	}
}

func TestEvaluationPerformanceCacheAndNoSendProofPreserveUnknowns(t *testing.T) {
	trajectory := agenteval.Trajectory{RunID: "run", FinishedAt: "2026-10-13T00:00:01Z"}
	appendPerformanceEvidence(&trajectory, nil, true, nil, false, false)
	if trajectory.Coverage["model_timing"] || trajectory.Coverage["native_stage_cache"] {
		t.Fatal("legacy absence became measured zero")
	}
	appendPerformanceEvidence(&trajectory, nil, true, nil, false, true)
	if !trajectory.Coverage["model_timing"] {
		t.Fatal("verified no-send evidence lost")
	}
	l, h, f := int64(4), int64(3), int64(0)
	start := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	query := audit.NewPerformanceObservation(sharedkernel.Scope{RunID: "run"}, "query", "knowledge_query", "succeeded", start, start.Add(43*time.Millisecond))
	query.CacheMode, query.CacheLookups, query.CacheHits, query.CacheFailures = "use", &l, &h, &f
	appendPerformanceEvidence(&trajectory, []audit.PerformanceObservation{query}, true, nil, false, false)
	if !trajectory.Coverage["native_stage_cache"] || *trajectory.Measurements.CacheLookups != 4 || *trajectory.Measurements.CacheHits != 3 {
		t.Fatal("actual native cache counters were not projected", trajectory.Measurements)
	}
}
