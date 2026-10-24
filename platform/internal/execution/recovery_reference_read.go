package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CurrentRecoveryStopReference selects provenance for the newly leased
// generation from one read snapshot. It neither dispatches nor grants rights,
// and never replaces the separate committed approval reference.
func (s *SQLStore) CurrentRecoveryStopReference(ctx context.Context, expected platformruntime.Run) (*RecoveryStopReference, error) {
	if s == nil || s.db == nil || expected.Status != platformruntime.StatusRunning || expected.Revision < 2 || expected.LeaseToken == "" || expected.AgentEndpoint == "" {
		return nil, platformruntime.ErrInvalidRequest
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
	if actual.Status != expected.Status || actual.Revision != expected.Revision || actual.LeaseToken != expected.LeaseToken ||
		actual.Scope != expected.Scope || actual.AgentEndpoint != expected.AgentEndpoint || !actual.LeaseUntil.After(now) ||
		stopHash(actual.RequestJSON) != stopHash(expected.RequestJSON) || stopHash(actual.ResumeInputJSON) != stopHash(expected.ResumeInputJSON) {
		return nil, platformruntime.ErrLeaseConflict
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event
 WHERE run_id=? AND event_type='recovery_stop_confirmed' ORDER BY seq DESC LIMIT 1`), actual.ID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // a new Run has no recovery provenance
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > contract.MaxRecoveryReferenceBytes {
		return nil, ErrStopEvidenceInvalid
	}
	var event struct {
		Revision  uint64                 `json:"revision"`
		Reference *RecoveryStopReference `json:"recovery_reference"`
	}
	if strictStopJSON(raw, &event) != nil || event.Revision == 0 || event.Revision >= 1<<53 {
		return nil, ErrStopEvidenceInvalid
	}
	if event.Revision+1 < actual.Revision {
		// A later, independently authorized waiting/resume generation does not
		// inherit an older stop's checkpoint snapshot or transient approval.
		var approved ApprovedToolResume
		if json.Unmarshal(actual.ResumeInputJSON, &approved) != nil || !approved.valid(actual.Scope) || approved.WaitingRevision <= event.Revision || approved.WaitingRevision+2 != actual.Revision {
			group, groupErr := readAgentGroupResumeReferenceTx(ctx, tx, actual, now)
			if groupErr != nil || group == nil || group.WaitingRevision <= event.Revision {
				return nil, ErrStopEvidenceInvalid
			}
			return nil, nil // a separately committed later group queue supersedes this stop
		}
		var committed bool
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event
 WHERE run_id=? AND event_type='status' AND payload::jsonb->>'from'='waiting'
 AND payload::jsonb->>'to'='running' AND payload::jsonb->>'revision'=?)`), actual.ID, strconv.FormatUint(actual.Revision-1, 10)).Scan(&committed); err != nil {
			return nil, err
		}
		if !committed {
			return nil, ErrStopEvidenceInvalid
		}
		return nil, nil
	}
	ref := event.Reference
	if event.Revision+1 != actual.Revision || ref == nil || !ref.valid() || len(ref.Checkpoints) == 0 ||
		ref.RunID != actual.ID || ref.ReadyRevision != event.Revision || ref.RequestHash != stopHash(actual.RequestJSON) ||
		ref.ResumeInputHash != stopHash(actual.ResumeInputJSON) || ref.LeaseHash == stopHash([]byte(actual.LeaseToken)) {
		return nil, ErrStopEvidenceInvalid
	}
	for _, checkpoint := range ref.Checkpoints {
		if !checkpoint.ExpiresAt.After(now) {
			return nil, ErrStopEvidenceInvalid
		}
	}
	return ref, nil
}
