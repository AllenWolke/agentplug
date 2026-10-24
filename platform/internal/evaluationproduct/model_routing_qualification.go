package evaluationproduct

import (
	"context"
	"encoding/json"
	"math"
	"time"
)

// RoutingCaseModelVerifier reads original execution/settled model receipts.
// Dataset labels and an Agent's own output cannot prove the evaluated model.
type RoutingCaseModelVerifier interface {
	VerifyRoutingCaseModel(context.Context, Scope, string, int, string, RoutingQualificationTarget) (RoutingQualifiedCase, error)
}

type RoutingQualifiedCase struct {
	BusinessInputSHA256 string
	QualityChecks       map[string]*bool
}

type RoutingQualificationTarget struct {
	AgentID                string `json:"agent_id"`
	AgentVersionID         string `json:"agent_version_id"`
	ExecutionContextSHA256 string `json:"execution_context_sha256"`
}

// VerifyModelRoutingQualification reuses the frozen product evidence validators.
// A maximum tier must be qualified on that tier and every lower tier. Success on
// complex cases does not prove simpler tasks are safe to route to the model.
// Reviewer-only expected.routing_complexity is never disclosed to the Agent.
func VerifyModelRoutingQualification(ctx context.Context, store Store, scope Scope, evidenceID, reportHash, modelVersion, tier string, models RoutingCaseModelVerifier, target RoutingQualificationTarget) error {
	return VerifyModelRoutingQualificationWithMaxAge(ctx, store, scope, evidenceID, reportHash, modelVersion, tier, models, target, 86400)
}

// Only the reviewed policy publication adapter supplies a retained source age.
// Browser readback and ordinary release gates keep their original 24h bound.
// This never changes measurement dates, metrics or native source verification.
func VerifyModelRoutingQualificationWithMaxAge(ctx context.Context, store Store, scope Scope, evidenceID, reportHash, modelVersion, tier string, models RoutingCaseModelVerifier, target RoutingQualificationTarget, maxAgeSeconds int64) error {
	if maxAgeSeconds < 86400 || maxAgeSeconds > 7*86400 {
		return ErrSnapshotInvalid
	}
	if store == nil || models == nil || !scope.valid() || !validID(evidenceID) || !validSHA256(reportHash) || !validID(modelVersion) ||
		(tier != "simple" && tier != "medium" && tier != "complex") || !validID(target.AgentID) || !validID(target.AgentVersionID) || !validSHA256(target.ExecutionContextSHA256) {
		return ErrSnapshotInvalid
	}
	row, err := store.Get(ctx, scope, KindEvidence, evidenceID)
	if err != nil {
		return err
	}
	var evidence EvidenceData
	if row.Scope != scope || row.Kind != KindEvidence || row.Status != "completed" || json.Unmarshal(row.Data, &evidence) != nil ||
		evidence.ReportHash != reportHash || evidence.MeasurementProtocol != IndependentVerdictProtocol || evidence.Gate.State != GatePass || !evidence.MetricsPresent || !evidence.ArtifactsPresent ||
		evidence.SampleCount < 20 || evidence.SampleCount > 1000 || evaluateEvidenceMaxAge(evidence, nil, time.Now().UTC(), time.Duration(maxAgeSeconds)*time.Second).State != GatePass {
		return ErrSnapshotInvalid
	}
	run, err := store.Get(ctx, scope, KindRun, evidence.RunID)
	if err != nil {
		return err
	}
	dataset, err := verifyEvidenceSnapshot(ctx, store, scope, run, evidence)
	if err != nil {
		return err
	}
	if err := verifyEvidenceCases(ctx, store, scope, evidence, dataset.Cases); err != nil {
		return err
	}
	// Unknown or missing required quality outcomes cannot qualify a cheap model.
	thresholds := routingQualityThresholds()
	reported := map[string]float64{}
	for _, metric := range evidence.Metrics {
		metricRow, err := store.Get(ctx, scope, KindMetric, metric.MetricID)
		if err != nil {
			return err
		}
		var definition MetricData
		if metricRow.Scope != scope || metricRow.Kind != KindMetric || metricRow.Status != "published" || json.Unmarshal(metricRow.Data, &definition) != nil {
			return ErrSnapshotInvalid
		}
		if minimum, required := thresholds[definition.MetricID]; required {
			formula, formulaErr := parseIndependentVerdictFormula(definition.Formula)
			if definition.Kind != "independent_verdict" || formulaErr != nil || formula.MetricID != definition.MetricID {
				return ErrSnapshotInvalid
			}
			if _, duplicate := reported[definition.MetricID]; duplicate {
				return ErrSnapshotInvalid
			}
			if metric.Status != "passed" || metric.Value == nil || math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0) || *metric.Value < minimum || *metric.Value > 1 {
				return ErrSnapshotInvalid
			}
			reported[definition.MetricID] = *metric.Value
		}
	}
	if len(reported) != len(thresholds) {
		return ErrSnapshotInvalid
	}
	seen := map[string]bool{}
	businessSeen := map[string]bool{}
	tiers := routingRequiredTiers(tier)
	tierCounts := map[string]int{}
	tierCorrect := map[string]map[string]int{}
	for index, raw := range dataset.Cases {
		item, err := decodeEvaluationCase(raw)
		if err != nil || item.Split != "frozen" && item.Split != "test" {
			return ErrSnapshotInvalid
		}
		var gold struct {
			Complexity string `json:"routing_complexity"`
		}
		if json.Unmarshal(item.Expected, &gold) != nil || !tiers[gold.Complexity] {
			return ErrSnapshotInvalid
		}
		tierCounts[gold.Complexity]++
		if tierCorrect[gold.Complexity] == nil {
			tierCorrect[gold.Complexity] = map[string]int{}
		}
		// A new case identifier around the same business input is not independent.
		hash := Checksum(item.Input)
		if seen[hash] {
			return ErrSnapshotInvalid
		}
		seen[hash] = true
		// Evidence validation above proves any reuse against the immutable
		// original Case. Keep the native execution verifier unchanged: it must
		// still read the actual old parent/index, not invent a new model run.
		parent, sourceIndex := evidence.RunID, index
		if item.Reuse != nil {
			parent, sourceIndex = item.Reuse.RunID, item.Reuse.Index
		}
		qualified, err := models.VerifyRoutingCaseModel(ctx, scope, parent, sourceIndex, modelVersion, target)
		if err != nil {
			return err
		}
		if !validSHA256(qualified.BusinessInputSHA256) || businessSeen[qualified.BusinessInputSHA256] {
			return ErrSnapshotInvalid
		}
		businessSeen[qualified.BusinessInputSHA256] = true
		for metric := range reported {
			value := qualified.QualityChecks[metric]
			if value == nil {
				return ErrSnapshotInvalid
			}
			if *value {
				tierCorrect[gold.Complexity][metric]++
			}
		}
	}
	// Published metric names/thresholds alone cannot establish quality. Compare
	// them with the independent, source-bound verdicts of every applicable case.
	return verifyRoutingTierQuality(tier, reported, tierCounts, tierCorrect)
}

func routingQualityThresholds() map[string]float64 {
	return map[string]float64{"task_success": .90, "domain_correctness": .90, "groundedness": .95, "faithfulness": .95, "citation_accuracy": .95}
}

func routingRequiredTiers(maximum string) map[string]bool {
	result := map[string]bool{}
	for _, tier := range []string{"simple", "medium", "complex"} {
		result[tier] = true
		if tier == maximum {
			return result
		}
	}
	return nil
}

// Do not let a strong tier hide an unqualified tier in an overall average.
func verifyRoutingTierQuality(maximum string, reported map[string]float64, counts map[string]int, correct map[string]map[string]int) error {
	tiers, thresholds := routingRequiredTiers(maximum), routingQualityThresholds()
	if len(tiers) == 0 || len(reported) != len(thresholds) || len(counts) != len(tiers) {
		return ErrSnapshotInvalid
	}
	total := 0
	for tier := range tiers {
		if counts[tier] < 20 {
			return ErrSnapshotInvalid
		}
		total += counts[tier]
		for metric, minimum := range thresholds {
			passed := correct[tier][metric]
			if passed < 0 || passed > counts[tier] || float64(passed)/float64(counts[tier]) < minimum {
				return ErrSnapshotInvalid
			}
		}
	}
	for metric, minimum := range thresholds {
		value, exists := reported[metric]
		if !exists || math.IsNaN(value) || math.IsInf(value, 0) || value < minimum || value > 1 {
			return ErrSnapshotInvalid
		}
		passed := 0
		for tier := range tiers {
			passed += correct[tier][metric]
		}
		if math.Abs(value-float64(passed)/float64(total)) > 1e-9 {
			return ErrSnapshotInvalid
		}
	}
	return nil
}
