package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type evidenceBoundsStore struct {
	Store
	reads int
}

func (s *evidenceBoundsStore) Get(context.Context, Scope, Kind, string) (Resource, error) {
	s.reads++
	return Resource{}, ErrNotFound
}

func TestEvidenceBoundsRejectInvalidCountsBeforeReadingCases(t *testing.T) {
	scope := Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "app-a"}
	for _, tc := range []struct {
		name                   string
		count, inputs, metrics int
	}{
		{"above_admission_ceiling", 10001, 10001, 1},
		{"dataset_count_mismatch", 1, 0, 1},
		{"metric_count_above_ceiling", 1, 1, 101},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &evidenceBoundsStore{}
			e := EvidenceData{RunID: "run-bounds", SampleCount: tc.count, CaseResultIDs: make([]string, tc.count), Metrics: make([]MetricOutcome, tc.metrics)}
			for i := range e.CaseResultIDs {
				e.CaseResultIDs[i] = caseResultID(e.RunID, i)
			}
			err := verifyEvidenceCases(context.Background(), store, scope, e, make([]json.RawMessage, tc.inputs))
			if !errors.Is(err, ErrSnapshotInvalid) || store.reads != 0 {
				t.Fatalf("invalid evidence read cases: err=%v reads=%d", err, store.reads)
			}
		})
	}
}
