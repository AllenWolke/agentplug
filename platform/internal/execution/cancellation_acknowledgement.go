package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

const cancellationAcknowledgementEvent = "cancellation_agent_stop_acknowledged"

// This receipt proves only remote exit. It is deliberately distinct from the
// settled stop proof used to finish cancellation and release session FIFO.
type cancellationAgentAcknowledgement struct {
	Version           string                  `json:"version"`
	Binding           cancellationStopBinding `json:"binding"`
	ExecutionRevision uint64                  `json:"execution_revision"`
}

type cancellationAcknowledgementStore interface {
	ReadCancellationAgentAcknowledgement(context.Context, platformruntime.Run) (uint64, bool, error)
	RecordCancellationAgentAcknowledgement(context.Context, platformruntime.Run, uint64) error
}

func sameCancellationGeneration(actual, expected platformruntime.Run) bool {
	return actual.Status == platformruntime.StatusCancelling && expected.Status == actual.Status &&
		actual.Scope == expected.Scope && actual.Revision == expected.Revision &&
		actual.LeaseToken != "" && actual.LeaseToken == expected.LeaseToken &&
		actual.AgentEndpoint == expected.AgentEndpoint && actual.IdempotencyKey == expected.IdempotencyKey &&
		bytes.Equal(actual.RequestJSON, expected.RequestJSON) && bytes.Equal(actual.ResumeInputJSON, expected.ResumeInputJSON)
}

func cancellationAcknowledgement(run platformruntime.Run, executionRevision uint64) cancellationAgentAcknowledgement {
	b := cancellationStopBinding{Version: "execution-cancellation-stop/v1", ScopeDigest: compensation.ScopeDigest(run.Scope),
		Revision: run.Revision, Source: "agent-stop-acknowledgement/v1", LeaseHash: stopHash([]byte(run.LeaseToken)),
		RequestHash: stopHash(run.RequestJSON), ResumeHash: stopHash(run.ResumeInputJSON)}
	raw, _ := json.Marshal([]any{executionRevision, b.LeaseHash, b.RequestHash, b.ResumeHash})
	b.SourceEvidence = stopHash(raw)
	return cancellationAgentAcknowledgement{Version: "execution-cancellation-agent-ack/v1", Binding: b, ExecutionRevision: executionRevision}
}

func readCancellationAcknowledgementTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, revision uint64) (bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type=? ORDER BY seq DESC LIMIT 1`), run.ID, cancellationAcknowledgementEvent).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var stored cancellationAgentAcknowledgement
	want := cancellationAcknowledgement(run, revision)
	if len(raw) > 2048 || strictStopJSON(raw, &stored) != nil || stored != want || !stored.Binding.matches(run) {
		return false, ErrStopEvidenceInvalid
	}
	return true, nil
}

func (s *SQLStore) ReadCancellationAgentAcknowledgement(ctx context.Context, expected platformruntime.Run) (uint64, bool, error) {
	if s == nil || s.db == nil || ctx == nil || expected.Scope.ValidateTrusted() != nil || expected.ID != expected.Scope.RunID {
		return 0, false, platformruntime.ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	actual, err := readExecutionRun(ctx, tx, expected.ID, " FOR SHARE")
	if err != nil {
		return 0, false, err
	}
	if !sameCancellationGeneration(actual, expected) {
		return 0, false, platformruntime.ErrRevisionConflict
	}
	// Absence needs no dispatch lookup: the normal undispatched cancellation
	// path must still work when there never was a remote generation to stop.
	var exists bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type=?)`), actual.ID, cancellationAcknowledgementEvent).Scan(&exists); err != nil {
		return 0, false, err
	}
	if !exists {
		return 0, false, tx.Commit()
	}
	revision, err := s.cancellationExecutionRevisionTx(ctx, tx, actual)
	if err != nil {
		return 0, false, err
	}
	found, err := readCancellationAcknowledgementTx(ctx, tx, actual, revision)
	if err != nil || !found {
		return 0, false, err
	}
	return revision, true, tx.Commit()
}

// Called only by the trusted dispatcher after validating the signed cancel
// response. No generic event/Agent endpoint can manufacture this receipt.
func (s *SQLStore) RecordCancellationAgentAcknowledgement(ctx context.Context, expected platformruntime.Run, executionRevision uint64) error {
	if s == nil || s.db == nil || ctx == nil || expected.Scope.ValidateTrusted() != nil || expected.ID != expected.Scope.RunID || executionRevision == 0 {
		return platformruntime.ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actual, err := readExecutionRun(ctx, tx, expected.ID, " FOR UPDATE")
	if err != nil {
		return err
	}
	if !sameCancellationGeneration(actual, expected) {
		return platformruntime.ErrRevisionConflict
	}
	revision, err := s.cancellationExecutionRevisionTx(ctx, tx, actual)
	if err != nil {
		return err
	}
	if executionRevision != revision {
		return platformruntime.ErrLeaseConflict
	}
	found, err := readCancellationAcknowledgementTx(ctx, tx, actual, revision)
	if err != nil {
		return err
	}
	if !found {
		raw, err := json.Marshal(cancellationAcknowledgement(actual, revision))
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,?)`), actual.ID, cancellationAcknowledgementEvent, raw, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
