package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (ref AgentGroupWaitReference) valid(runID string) bool {
	if ref.Version != "agent-group-resume/v1" || ref.WaitingRevision < 2 || ref.WaitingRevision != ref.Handoff.ExecutionRevision+1 || ref.OriginOperation != ref.Handoff.OriginOperation || ref.Handoff.ValidateStoredShape(runID, ref.WaitingRevision-1) != nil || len(ref.Checkpoints) < 1 || len(ref.Checkpoints) > 128 {
		return false
	}
	seen := map[string]bool{}
	previous := ""
	found := false
	for _, cp := range ref.Checkpoints {
		if cp.Validate(ref.Handoff.ExecutionRevision) != nil || seen[cp.StateKey] || cp.StateKey <= previous {
			return false
		}
		previous = cp.StateKey
		seen[cp.StateKey] = true
		h := ref.Handoff.Checkpoint
		if cp.StateKey == h.StateKey && cp.Revision == h.Revision && cp.SchemaID == h.SchemaID && cp.ContentHash == h.ContentHash && cp.ExecutionRevision == h.ExecutionRevision && cp.ExpiresAt.Equal(h.ExpiresAt) {
			found = true
		}
	}
	return found
}

// CurrentAgentGroupResumeReference reads the exact committed queue provenance
// from one snapshot. It accepts no caller-provided receipt and issues no token.
func (s *SQLStore) CurrentAgentGroupResumeReference(ctx context.Context, expected platformruntime.Run) (*AgentGroupWaitReference, error) {
	if s == nil || s.db == nil || expected.Status != platformruntime.StatusRunning || expected.LeaseToken == "" {
		return nil, platformruntime.ErrInvalidRequest
	}
	var marker struct {
		Version string `json:"version"`
	}
	if len(expected.ResumeInputJSON) == 0 {
		return nil, nil
	}
	if json.Unmarshal(expected.ResumeInputJSON, &marker) != nil {
		return nil, platformruntime.ErrInvalidRequest
	}
	if marker.Version != "agent-group-resume/v1" {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actual, err := readExecutionRun(ctx, tx, expected.ID, "")
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if actual.Status != expected.Status || actual.Revision != expected.Revision || actual.Scope != expected.Scope || actual.LeaseToken != expected.LeaseToken || actual.AgentEndpoint != expected.AgentEndpoint || !actual.LeaseUntil.After(now) || stopHash(actual.RequestJSON) != stopHash(expected.RequestJSON) || stopHash(actual.ResumeInputJSON) != stopHash(expected.ResumeInputJSON) {
		return nil, platformruntime.ErrLeaseConflict
	}
	return readAgentGroupResumeReferenceTx(ctx, tx, actual, now)
}

func readAgentGroupResumeReferenceTx(ctx context.Context, tx *sql.Tx, actual platformruntime.Run, now time.Time) (*AgentGroupWaitReference, error) {
	var ref AgentGroupWaitReference
	if len(actual.ResumeInputJSON) > 128<<10 || strictStopJSON(actual.ResumeInputJSON, &ref) != nil || !ref.valid(actual.ID) || ref.WaitingRevision+2 != actual.Revision || ref.Handoff.LeaseTokenHash == stopHash([]byte(actual.LeaseToken)) {
		return nil, ErrStopEvidenceInvalid
	}
	var revision uint64
	var eventType string
	var raw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,event_payload FROM platform_execution_outcome WHERE run_id=?`), actual.ID).Scan(&revision, &eventType, &raw); err != nil {
		return nil, err
	}
	if revision != ref.WaitingRevision || eventType != "waiting" || len(raw) > 128<<10 {
		return nil, ErrStopEvidenceInvalid
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil || !bytes.Equal(payload["source"], []byte(`"platform_agent_gateway"`)) || payload["handoff"] != nil {
		return nil, ErrStopEvidenceInvalid
	}
	var committed AgentGroupWaitReference
	if strictStopJSON(payload["group_wait_reference"], &committed) != nil {
		return nil, ErrStopEvidenceInvalid
	}
	a, _ := json.Marshal(ref)
	b, _ := json.Marshal(committed)
	if !bytes.Equal(a, b) {
		return nil, ErrStopEvidenceInvalid
	}
	var queued bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type='status' AND payload::jsonb->>'from'='waiting' AND payload::jsonb->>'to'='running' AND payload::jsonb->>'reason'='agent_group_terminal' AND payload::jsonb->>'revision'=?)`), actual.ID, strconv.FormatUint(actual.Revision-1, 10)).Scan(&queued); err != nil {
		return nil, err
	}
	if !queued {
		return nil, ErrStopEvidenceInvalid
	}
	for _, cp := range ref.Checkpoints {
		if !cp.ExpiresAt.After(now) {
			return nil, ErrStopEvidenceInvalid
		}
	}
	return &ref, nil
}
