package audit

import (
	"strconv"
	"testing"

	agenteval "github.com/lexagent/agent-evaluation"
)

// Test sources are prepared for the consolidated verification phase.
func TestPerformanceMergePreservesOriginalMeasurementAndRejectsConflicts(t *testing.T) {
	scope := performanceFixtureScope()
	one := performanceFixture(scope)
	merged, err := MergePerformanceEvidence(scope, []PerformanceObservation{one}, []PerformanceObservation{one})
	if err != nil || len(merged) != 1 || merged[0].DurationMS != one.DurationMS {
		t.Fatalf("exact duplicate must preserve the original observation: %v", err)
	}
	changed := one
	changed.CacheMode = "bypass"
	if _, err := MergePerformanceEvidence(scope, []PerformanceObservation{one}, []PerformanceObservation{changed}); err == nil {
		t.Fatal("conflicting durable receipt was accepted")
	}
	foreign := scope
	foreign.RunID = "another-run"
	if _, err := MergePerformanceEvidence(foreign, nil, []PerformanceObservation{one}); err == nil {
		t.Fatal("measurement crossed Run identity")
	}
}

func TestPerformanceMergeAcceptsDuplicateAtLimitButRejectsAnAdditionalMeasurement(t *testing.T) {
	scope := performanceFixtureScope()
	prototype := performanceFixture(scope)
	items := make([]PerformanceObservation, performanceObservationLimit)
	for index := range items {
		items[index] = prototype
		items[index].StepID = NewPerformanceObservation(scope, strconv.Itoa(index), prototype.Kind,
			prototype.Status, prototype.StartedAt, prototype.FinishedAt).StepID
	}
	if merged, err := MergePerformanceEvidence(scope, items, []PerformanceObservation{items[0]}); err != nil || len(merged) != len(items) {
		t.Fatalf("exact duplicate after the limit should not consume another slot: %v", err)
	}
	extra := prototype
	extra.StepID = NewPerformanceObservation(scope, "extra", prototype.Kind,
		prototype.Status, prototype.StartedAt, prototype.FinishedAt).StepID
	if _, err := MergePerformanceEvidence(scope, items, []PerformanceObservation{extra}); err == nil {
		t.Fatal("additional measurement exceeded the projection bound")
	}
	if merged, complete, err := MergePerformanceEvidenceProfile(scope, items, []PerformanceObservation{extra}, agenteval.EvidenceReadProfileLargeV1); err != nil || !complete || len(merged) != len(items)+1 {
		t.Fatal("explicit large profile did not preserve distinct observations", complete, err)
	}
	if merged, complete, err := MergePerformanceEvidenceProfile(scope, items, []PerformanceObservation{extra}, ""); err != nil || complete || len(merged) != len(items) {
		t.Fatal("bounded profile did not mark truncated measurement evidence", complete, err)
	}
	if _, _, err := MergePerformanceEvidenceProfile(scope, nil, nil, "unlimited"); err == nil {
		t.Fatal("arbitrary performance read capacity accepted")
	}
}
