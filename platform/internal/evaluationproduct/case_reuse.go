package evaluationproduct

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// CaseReuseReference selects an immutable, platform-produced measurement.
// It is dataset metadata, never Agent input, model output or permission.
type CaseReuseReference struct {
	Version    string `json:"version"`
	RunID      string `json:"run_id"`
	Index      int    `json:"index"`
	ResultHash string `json:"result_hash"`
}

func (ref *CaseReuseReference) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Version    string `json:"version"`
		RunID      string `json:"run_id"`
		Index      *int   `json:"index"`
		ResultHash string `json:"result_hash"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(new(any)) != io.EOF || wire.Index == nil {
		return ErrInvalid
	}
	*ref = CaseReuseReference{Version: wire.Version, RunID: wire.RunID, Index: *wire.Index, ResultHash: wire.ResultHash}
	if !validCaseReuseReference(*ref) {
		return ErrInvalid
	}
	return nil
}

func validCaseReuseReference(ref CaseReuseReference) bool {
	return ref.Version == "evaluation-case-reuse/v1" && validID(ref.RunID) &&
		ref.Index >= 0 && ref.Index < 10000 && validSHA256(ref.ResultHash)
}

// Resolvers live for one scoped Run/read, avoiding repeated full snapshot
// loads while retaining independent, current authorization at API boundaries.
type caseReuseResolver struct {
	store     Store
	target    ExecutionRequest
	snapshots map[string]ExecutionRequest
}

func newCaseReuseResolver(store Store, target ExecutionRequest) *caseReuseResolver {
	return &caseReuseResolver{store: store, target: target, snapshots: map[string]ExecutionRequest{}}
}

func (r *caseReuseResolver) source(ctx context.Context, ref CaseReuseReference) (ExecutionRequest, error) {
	if !validCaseReuseReference(ref) || ref.RunID == r.target.RunID() {
		return ExecutionRequest{}, snapshotInvalid("invalid case reuse identity")
	}
	if previous, ok := r.snapshots[ref.RunID]; ok {
		return previous, nil
	}
	run, err := getScopedResource(ctx, r.store, r.target.Scope(), KindRun, ref.RunID)
	if err != nil {
		return ExecutionRequest{}, err
	}
	if run.Status != "succeeded" && run.Status != "failed" && run.Status != "cancelled" {
		return ExecutionRequest{}, snapshotInvalid("case reuse source is not terminal")
	}
	previous, err := ResolveHistoricalExecutionSnapshot(ctx, r.store, r.target.Scope(), run)
	if err != nil {
		return ExecutionRequest{}, err
	}
	if previous.AgentID() != r.target.AgentID() || previous.AgentVersionID() != r.target.AgentVersionID() ||
		previous.InstallationID() != r.target.InstallationID() || previous.InstallationRevision() != r.target.InstallationRevision() ||
		previous.dataset.SourceType != r.target.dataset.SourceType || len(previous.metrics) != len(r.target.metrics) {
		return ExecutionRequest{}, snapshotInvalid("case reuse evaluator binding differs")
	}
	for i, old := range previous.metrics {
		current := r.target.metrics[i]
		if old.ID != current.ID || old.Revision != current.Revision || old.FormulaHash != current.FormulaHash ||
			old.Kind != current.Kind || old.PluginID != current.PluginID || old.PluginVersion != current.PluginVersion || old.PluginDigest != current.PluginDigest {
			return ExecutionRequest{}, snapshotInvalid("case reuse metric binding differs")
		}
	}
	r.snapshots[ref.RunID] = previous
	return previous, nil
}

// prepare proves the complete original Case and returns a source-attributed
// result. It never invokes an Agent, writes an output artifact, or settles fees.
// Only leaf measurements may be referenced: callers flatten earlier reuse
// provenance explicitly instead of creating an unbounded reference graph.
func (r *caseReuseResolver) prepare(ctx context.Context, raw json.RawMessage, index int) (CaseResultData, error) {
	current, err := decodeEvaluationCase(raw)
	if err != nil || current.Reuse == nil {
		return CaseResultData{}, snapshotInvalid("case reuse reference missing")
	}
	ref := *current.Reuse
	previous, err := r.source(ctx, ref)
	if err != nil {
		return CaseResultData{}, err
	}
	if ref.Index >= len(previous.dataset.Cases) {
		return CaseResultData{}, snapshotInvalid("case reuse index exceeds source dataset")
	}
	oldRaw := previous.dataset.Cases[ref.Index]
	oldInput, err := decodeEvaluationCase(oldRaw)
	if err != nil || oldInput.Reuse != nil {
		return CaseResultData{}, snapshotInvalid("case reuse must refer to an original measurement")
	}
	current.Reuse = nil
	a, ae := contentHash(current)
	b, be := contentHash(oldInput)
	if ae != nil || be != nil || a != b {
		return CaseResultData{}, snapshotInvalid("case reuse input, gold or case identity differs")
	}
	row, err := getScopedResource(ctx, r.store, r.target.Scope(), KindCaseResult, caseResultID(ref.RunID, ref.Index))
	if err != nil {
		return CaseResultData{}, err
	}
	value, err := decodeCaseResult(row)
	hash, hashErr := contentHash(json.RawMessage(row.Data))
	if err != nil || hashErr != nil || hash != ref.ResultHash || row.CreatedBy != "platform-evaluation-product" ||
		value.ReusedFrom != nil || value.RunID != ref.RunID || value.Index != ref.Index ||
		value.InputHash != Checksum(oldRaw) || len(value.Metrics) != len(r.target.metrics) {
		return CaseResultData{}, snapshotInvalid("case reuse original result does not verify")
	}
	for i, metric := range value.Metrics {
		if metric.MetricID != r.target.metrics[i].ID {
			return CaseResultData{}, snapshotInvalid("case reuse result metric differs")
		}
	}
	value.RunID, value.Index, value.InputHash = r.target.RunID(), index, Checksum(raw)
	value.ProducedAt, value.ReusedFrom = time.Now().UTC(), &ref
	return value, nil
}

func (r *caseReuseResolver) verify(ctx context.Context, raw json.RawMessage, index int, actual CaseResultData) error {
	input, err := decodeEvaluationCase(raw)
	if err != nil {
		return err
	}
	if input.Reuse == nil && actual.ReusedFrom == nil {
		return nil
	}
	if input.Reuse == nil || actual.ReusedFrom == nil || *input.Reuse != *actual.ReusedFrom {
		return snapshotInvalid("case reuse result provenance differs from dataset")
	}
	expected, err := r.prepare(ctx, raw, index)
	if err != nil {
		return err
	}
	return verifyPreparedCaseReuse(expected, actual)
}

func verifyPreparedCaseReuse(expected, actual CaseResultData) error {
	expected.ProducedAt = actual.ProducedAt
	a, ae := contentHash(expected)
	b, be := contentHash(actual)
	if ae != nil || be != nil || a != b {
		return snapshotInvalid("reused case differs from original measurement")
	}
	return nil
}

func (r *Runner) authorizeCaseReuse(ctx context.Context, request ExecutionRequest, index int, input json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	authority, ok := r.invoker.(EvaluationCaseReuseAuthorizer)
	if !ok {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, r.options.CaseTimeout)
	defer cancel()
	return authority.AuthorizeEvaluationCaseReuse(ctx, InvocationRequest{
		Scope: request.Scope(), RunID: request.RunID(), CaseIndex: index,
		IdempotencyKey: fmt.Sprintf("%s.case.%d", request.IdempotencyKey(), index),
		AgentID:        request.AgentID(), AgentVersionID: request.AgentVersionID(),
		InstallationID: request.InstallationID(), InstallationRevision: request.InstallationRevision(),
		Input: append(json.RawMessage(nil), input...),
	})
}
