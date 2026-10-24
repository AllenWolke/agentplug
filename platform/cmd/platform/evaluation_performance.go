package main

import (
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/platform/internal/audit"
)

// Optional performance evidence uses the existing language-neutral event and
// measurement contract. Historical missing timings are never synthesized.
func appendPerformanceEvidence(t *agenteval.Trajectory, items []audit.PerformanceObservation, complete bool,
	usageSteps []string, usageLinksComplete, noModelProof bool) {
	if t.Coverage == nil {
		t.Coverage = map[string]bool{}
	}
	if !complete && len(items) > 0 {
		t.Missing = append(t.Missing, "performance_observations_truncated")
		t.Complete = false
	}
	var lookups, hits, queries int64
	modelSteps := map[string]int{}
	modelAttempts := 0
	for _, o := range items {
		duration := o.DurationMS
		e := agenteval.Event{RunID: o.RunID, StepID: o.StepID, Kind: o.Kind, Status: o.Status, DurationMS: &duration,
			StartedAt: o.StartedAt.UTC().Format(time.RFC3339Nano), FinishedAt: o.FinishedAt.UTC().Format(time.RFC3339Nano),
			Arguments: map[string]any{"observation_version": o.Version, "timing_source": o.TimingSource}}
		if o.Kind == "model_gateway" {
			modelAttempts++
			e.ResourceIDs = []string{o.ModelVersionID}
			e.Arguments["operation"], e.Arguments["usage_step_id"] = o.Operation, o.UsageStepID
			if o.Status == "succeeded" {
				modelSteps[o.UsageStepID]++
			}
		} else if o.Kind == "knowledge_query" {
			queries++
			lookups += *o.CacheLookups
			hits += *o.CacheHits
			e.Arguments["cache_mode"] = o.CacheMode
			e.Arguments["cache_lookups"], e.Arguments["cache_hits"], e.Arguments["cache_failures"] = *o.CacheLookups, *o.CacheHits, *o.CacheFailures
		}
		t.Events = append(t.Events, e)
	}
	// Exactly one observation must match every confirmed usage step. A missing
	// call cannot be hidden by an unrelated failed call or replayed receipt.
	modelComplete := complete && t.FinishedAt != "" && usageLinksComplete && len(usageSteps) > 0
	for _, id := range usageSteps {
		if modelSteps[id] != 1 {
			modelComplete = false
		}
	}
	if noModelProof && complete && t.FinishedAt != "" && modelAttempts == 0 {
		modelComplete = true
	}
	t.Coverage["model_timing"] = modelComplete
	t.Coverage["native_stage_cache"] = complete && queries > 0
	if t.Coverage["native_stage_cache"] {
		t.Measurements.CacheHits, t.Measurements.CacheLookups = &hits, &lookups
	}
}
