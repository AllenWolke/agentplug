package evaluationproduct

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	agenteval "github.com/lexagent/agent-evaluation"
)

// Derived datasets retain current object-level access to all source Runs.
// Application-level evaluation rights never grant business-data access.
type SourceAuthorizer interface {
	AuthorizeSources(context.Context, Actor, []agenteval.SourceReference) error
}

func JudgeDatasetReferences(d DatasetData) ([]agenteval.SourceReference, error) {
	refs := []agenteval.SourceReference{}
	for _, raw := range d.Cases {
		var sample struct {
			Input json.RawMessage `json:"input"`
		}
		if json.Unmarshal(raw, &sample) != nil {
			return nil, ErrInvalid
		}
		var tag struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(sample.Input, &tag) != nil {
			return nil, ErrInvalid
		}
		if !agenteval.IsJudgeInputVersion(tag.Version) {
			continue
		}
		if d.SourceType != "imported_redacted" {
			return nil, ErrInvalid
		}
		var input agenteval.JudgeInput
		decoder := json.NewDecoder(bytes.NewReader(sample.Input))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil {
			return nil, ErrInvalid
		}
		ref, err := input.SourceReference()
		if err != nil {
			return nil, ErrInvalid
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
func (m *Module) authorizeDatasetSources(ctx context.Context, a Actor, d DatasetData) error {
	refs, err := JudgeDatasetReferences(d)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	if m.sourceAuthorizer == nil {
		return ErrUnavailable
	}
	return m.sourceAuthorizer.AuthorizeSources(ctx, a, refs)
}
func (m *Module) protectSources(w http.ResponseWriter, r *http.Request, a Actor, row Resource) bool {
	if err := m.authorizeResourceSources(r.Context(), a, row, 0); err != nil {
		m.inspectionError(w, err)
		return false
	}
	return true
}
func (m *Module) authorizeResourceSources(ctx context.Context, a Actor, row Resource, depth int) error {
	if depth > 4 {
		return ErrInvalid
	}
	var link struct {
		DatasetID  string `json:"dataset_id"`
		SuiteID    string `json:"suite_id"`
		RunID      string `json:"run_id"`
		EvidenceID string `json:"evidence_id"`
	}
	if row.Kind == KindDataset {
		var d DatasetData
		if json.Unmarshal(row.Data, &d) != nil {
			return ErrInvalid
		}
		return m.authorizeDatasetSources(ctx, a, d)
	}
	if json.Unmarshal(row.Data, &link) != nil {
		return ErrInvalid
	}
	var kind Kind
	var id string
	switch row.Kind {
	case KindSuite:
		kind, id = KindDataset, link.DatasetID
	case KindRun, KindEvidence:
		kind, id = KindSuite, link.SuiteID
	case KindCaseResult:
		kind, id = KindRun, link.RunID
	case KindReview, KindBaseline:
		kind, id = KindEvidence, link.EvidenceID
	default:
		return nil
	}
	if !validID(id) {
		return ErrInvalid
	}
	parent, err := m.store.Get(ctx, a.Scope, kind, id)
	if err != nil {
		return err
	}
	return m.authorizeResourceSources(ctx, a, parent, depth+1)
}
