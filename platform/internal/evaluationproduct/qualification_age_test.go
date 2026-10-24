package evaluationproduct

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRetainedQualificationAgePreservesOrdinaryGateAndProvenance(t *testing.T) {
	now := time.Now().UTC()
	base := EvidenceData{MeasurementProtocol: IndependentVerdictProtocol, RunID: "original-measurement", Status: "succeeded", SourceType: "imported_redacted", ProviderMode: "real", SampleCount: 1, CaseResultIDs: []string{"case-1"}, MetricsPresent: true, ArtifactsPresent: true, ReportHash: strings.Repeat("a", 64), SuiteSnapshotHash: strings.Repeat("b", 64), DatasetContentHash: strings.Repeat("c", 64), ProducedAt: now.Add(-26 * time.Hour), Metrics: []MetricOutcome{{MetricID: "domain_correctness", Status: "passed", Value: floatPointer(1), Direction: "higher_is_better"}}}
	if evaluateEvidence(base, nil, now).State != GateBlocked {
		t.Fatal("ordinary 24h gate changed")
	}
	if evaluateEvidenceMaxAge(base, nil, now, 7*24*time.Hour).State != GatePass {
		t.Fatal("explicit retained measurement rejected")
	}
	for name, mutate := range map[string]func(*EvidenceData){
		"expired":        func(e *EvidenceData) { e.ProducedAt = now.Add(-7*24*time.Hour - time.Second) },
		"future":         func(e *EvidenceData) { e.ProducedAt = now.Add(time.Second) },
		"no-date":        func(e *EvidenceData) { e.ProducedAt = time.Time{} },
		"no-artifact":    func(e *EvidenceData) { e.ArtifactsPresent = false },
		"mock":           func(e *EvidenceData) { e.ProviderMode = "mock" },
		"missing-cases":  func(e *EvidenceData) { e.CaseResultIDs = nil },
		"bad-hash":       func(e *EvidenceData) { e.ReportHash = "invalid" },
		"unknown-metric": func(e *EvidenceData) { e.Metrics = nil },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if evaluateEvidenceMaxAge(value, nil, now, 7*24*time.Hour).State == GatePass {
				t.Fatal("retention bypassed original provenance check")
			}
		})
	}
	for _, bound := range []time.Duration{0, time.Hour, 8 * 24 * time.Hour} {
		if evaluateEvidenceMaxAge(base, nil, now, bound).State != GateBlocked {
			t.Fatal("invalid retention bound accepted")
		}
	}
	before := base
	_ = evaluateEvidenceMaxAge(base, nil, now, 7*24*time.Hour)
	if !reflect.DeepEqual(before, base) {
		t.Fatal("original measurement mutated")
	}
}
