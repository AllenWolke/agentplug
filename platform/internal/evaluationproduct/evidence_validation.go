package evaluationproduct

import (
	"context"
	"encoding/json"
	"math"
)

type caseEvidenceHashInput struct {
	ID     string         `json:"id"`
	Result CaseResultData `json:"result"`
}

// evaluationReportHash binds the product report to the frozen inputs and each
// persisted case result, including per-metric outcomes and artifact hashes.
func evaluationReportHash(evidence EvidenceData, cases []CaseResultData) (string, error) {
	ids := make([]string, len(cases))
	bound := make([]caseEvidenceHashInput, len(cases))
	for i, result := range cases {
		ids[i] = caseResultID(evidence.RunID, i)
		bound[i] = caseEvidenceHashInput{ID: ids[i], Result: result}
	}
	payload := struct {
		RunID              string                  `json:"run_id"`
		SuiteID            string                  `json:"suite_id"`
		SuiteSnapshotHash  string                  `json:"suite_snapshot_hash"`
		DatasetContentHash string                  `json:"dataset_content_hash"`
		AgentVersionID     string                  `json:"agent_version_id"`
		ProviderMode       string                  `json:"provider_mode"`
		SourceType         string                  `json:"source_type"`
		CitationGrounding  string                  `json:"citation_grounding"`
		DomainGrounding    string                  `json:"domain_grounding"`
		Metrics            []MetricOutcome         `json:"metrics"`
		CaseResults        []caseEvidenceHashInput `json:"case_results"`
	}{evidence.RunID, evidence.SuiteID, evidence.SuiteSnapshotHash, evidence.DatasetContentHash, evidence.AgentVersionID,
		evidence.ProviderMode, evidence.SourceType, evidence.CitationGrounding, evidence.DomainGrounding, evidence.Metrics, bound}
	return contentHash(payload)
}

func verifyEvidenceCases(ctx context.Context, store Store, scope Scope, evidence EvidenceData, inputs []json.RawMessage) error {
	if store == nil || !scope.valid() || !validID(evidence.RunID) || evidence.SampleCount <= 0 || len(evidence.CaseResultIDs) != evidence.SampleCount || len(evidence.Metrics) == 0 {
		return ErrSnapshotInvalid
	}
	results := make([]CaseResultData, evidence.SampleCount)
	for i, id := range evidence.CaseResultIDs {
		if id != caseResultID(evidence.RunID, i) {
			return snapshotInvalid("evidence case result identity mismatch")
		}
		row, err := store.Get(ctx, scope, KindCaseResult, id)
		if err != nil || row.Scope != scope || row.ID != id || row.Kind != KindCaseResult {
			return snapshotInvalid("evidence case result is missing")
		}
		result, err := decodeCaseResult(row)
		if err != nil || result.RunID != evidence.RunID || result.Index != i || len(result.Metrics) != len(evidence.Metrics) || len(inputs) != evidence.SampleCount || result.InputHash != Checksum(inputs[i]) {
			return snapshotInvalid("evidence case result is invalid")
		}
		for metricIndex, metric := range evidence.Metrics {
			caseMetric := result.Metrics[metricIndex]
			if caseMetric.MetricID != metric.MetricID || !validMetricOutcome(caseMetric) {
				return snapshotInvalid("case metric outcome differs from report")
			}
		}
		results[i] = result
	}
	refs := make([]MetricSnapshot, len(evidence.Metrics))
	for i, metric := range evidence.Metrics {
		if !validMetricOutcome(metric) {
			return snapshotInvalid("aggregate metric outcome is invalid")
		}
		refs[i] = MetricSnapshot{ID: metric.MetricID}
	}
	aggregated := aggregateCaseMetrics(refs, results)
	if !sameMetricOutcomes(aggregated, evidence.Metrics) {
		return snapshotInvalid("aggregate metrics do not match case outcomes")
	}
	hash, err := evaluationReportHash(evidence, results)
	if err != nil || hash != evidence.ReportHash || !validSHA256(evidence.ReportHash) {
		return snapshotInvalid("evaluation report hash mismatch")
	}
	return nil
}

func verifyEvidenceSnapshot(ctx context.Context, store Store, scope Scope, run Resource, evidence EvidenceData) (DatasetSnapshot, error) {
	if run.Kind != KindRun || run.Scope != scope || run.ID != evidence.RunID || run.Status != "succeeded" {
		return DatasetSnapshot{}, snapshotInvalid("evidence run identity or state is invalid")
	}
	var runData RunData
	if err := decodeSnapshotJSON(run.Data, &runData); err != nil || runData.ExecutionState != "succeeded" || runData.SuiteID != evidence.SuiteID || runData.AgentID == "" || runData.AgentVersionID != evidence.AgentVersionID {
		return DatasetSnapshot{}, snapshotInvalid("evidence run binding is invalid")
	}
	suiteRow, err := getScopedResource(ctx, store, scope, KindSuite, evidence.SuiteID)
	if err != nil {
		return DatasetSnapshot{}, err
	}
	if suiteRow.Status != "published" {
		return DatasetSnapshot{}, snapshotInvalid("evidence suite is not published")
	}
	var suiteData SuiteData
	if err := decodeSnapshotJSON(suiteRow.Data, &suiteData); err != nil {
		return DatasetSnapshot{}, snapshotInvalid("evidence suite data is malformed")
	}
	if err := validateSuiteSnapshot(suiteData); err != nil {
		return DatasetSnapshot{}, err
	}
	snapshot, err := decodeSuiteSnapshot(suiteData.Snapshot)
	if err != nil || snapshot.snapshotHash != suiteData.SnapshotHash || suiteData.SnapshotHash != evidence.SuiteSnapshotHash ||
		suiteData.AgentID != runData.AgentID || suiteData.AgentVersionID != evidence.AgentVersionID ||
		!sameOrderedStrings(suiteData.MetricIDs, snapshot.metricIDs()) || !validSHA256(evidence.DatasetContentHash) || snapshot.DatasetHash != evidence.DatasetContentHash {
		return DatasetSnapshot{}, snapshotInvalid("evidence does not match the frozen suite snapshot")
	}
	datasetRow, err := getScopedResource(ctx, store, scope, KindDataset, snapshot.DatasetID)
	if err != nil {
		return DatasetSnapshot{}, err
	}
	if datasetRow.Revision != snapshot.DatasetRevision {
		return DatasetSnapshot{}, ErrConflict
	}
	dataset, err := verifyDataset(datasetRow, snapshot)
	if err != nil || dataset.ContentHash != evidence.DatasetContentHash || dataset.SourceType != evidence.SourceType {
		return DatasetSnapshot{}, snapshotInvalid("evidence dataset differs from frozen snapshot")
	}
	if len(evidence.Metrics) != len(snapshot.Metrics) {
		return DatasetSnapshot{}, snapshotInvalid("evidence metric set differs from frozen suite")
	}
	for i, reference := range snapshot.Metrics {
		if evidence.Metrics[i].MetricID != reference.ID {
			return DatasetSnapshot{}, snapshotInvalid("evidence metric order differs from frozen suite")
		}
		metricRow, err := getScopedResource(ctx, store, scope, KindMetric, reference.ID)
		if err != nil {
			return DatasetSnapshot{}, err
		}
		if metricRow.Revision != reference.Revision {
			return DatasetSnapshot{}, ErrConflict
		}
		if _, err := verifyMetric(metricRow, reference); err != nil {
			return DatasetSnapshot{}, err
		}
	}
	return dataset, nil
}

func validMetricOutcome(metric MetricOutcome) bool {
	if !validID(metric.MetricID) || (metric.Status != "passed" && metric.Status != "blocked" && metric.Status != "unknown") ||
		(metric.Direction != "higher_is_better" && metric.Direction != "lower_is_better") || math.IsNaN(metric.AllowedRegression) ||
		math.IsInf(metric.AllowedRegression, 0) || metric.AllowedRegression < 0 || metric.AllowedRegression > 1 {
		return false
	}
	return metric.Value == nil || (!math.IsNaN(*metric.Value) && !math.IsInf(*metric.Value, 0))
}

func sameMetricOutcomes(left, right []MetricOutcome) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].MetricID != right[i].MetricID || left[i].Status != right[i].Status || left[i].Direction != right[i].Direction || left[i].AllowedRegression != right[i].AllowedRegression {
			return false
		}
		if left[i].Value == nil || right[i].Value == nil {
			if left[i].Value != nil || right[i].Value != nil {
				return false
			}
		} else if *left[i].Value != *right[i].Value {
			return false
		}
	}
	return true
}
