package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// failStoppedRecoveryTx consumes only an already verified actual stop. Missing
// State proves no safe continuation, never absence of prior side effects.
// The caller owns Run UPDATE and has checked the complete descendant barrier.
func (s *SQLStore) failStoppedRecoveryTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, reference RecoveryStopReference, proof *StopEvidence) (platformruntime.Run, error) {
	if tx == nil || run.Status != platformruntime.StatusRecovering || run.LeaseToken == "" ||
		!reference.valid() || reference.RunID != run.ID || reference.ReadyRevision != run.Revision+1 ||
		len(reference.Checkpoints) != 0 || s.recoverySettlement == nil {
		return platformruntime.Run{}, platformruntime.ErrInvalidTransition
	}
	if err := s.recoverySettlement(ctx, run.Scope); err != nil {
		return platformruntime.Run{}, err
	}
	var owner, token string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(run.Scope)).Scan(&owner, &token); err != nil {
		return platformruntime.Run{}, err
	}
	if owner != run.ID || token != run.LeaseToken {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	if proof != nil {
		payload, err := json.Marshal(proof)
		if err != nil {
			return platformruntime.Run{}, err
		}
		if _, err := s.dbProofEvent(tx, run.ID, payload); err != nil {
			return platformruntime.Run{}, err
		}
	}
	const code = "RECOVERY_STATE_UNAVAILABLE"
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='failed',revision=revision+1,lease_token='',lease_until=NULL,updated_at=? WHERE run_id=? AND status='recovering' AND revision=? AND lease_token=?`), now, run.ID, run.Revision, run.LeaseToken)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if count, err := result.RowsAffected(); err != nil {
		return platformruntime.Run{}, err
	} else if count != 1 {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	stopPayload, err := json.Marshal(map[string]any{"revision": run.Revision + 1, "code": code, "stop_reference": reference})
	if err != nil {
		return platformruntime.Run{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), run.ID, "recovery_unavailable_stop_confirmed", stopPayload, now); err != nil {
		return platformruntime.Run{}, err
	}
	statusPayload, _ := json.Marshal(map[string]any{"from": "recovering", "to": "failed", "revision": run.Revision + 1, "code": code})
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), run.ID, "status", statusPayload, now); err != nil {
		return platformruntime.Run{}, err
	}
	failurePayload, _ := json.Marshal(map[string]any{"code": code, "source": "platform_recovery", "retryable": false})
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_outcome(run_id,revision,output_json,event_type,event_payload,projection_pending) VALUES (?,?,?,?,?,FALSE) ON CONFLICT (run_id) DO UPDATE SET revision=EXCLUDED.revision,output_json=EXCLUDED.output_json,event_type=EXCLUDED.event_type,event_payload=EXCLUDED.event_payload,projection_pending=EXCLUDED.projection_pending`), run.ID, run.Revision+1, []byte(`{}`), "task_failed", failurePayload); err != nil {
		return platformruntime.Run{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), run.ID, "task_failed", failurePayload, now); err != nil {
		return platformruntime.Run{}, err
	}
	run.Status, run.Revision, run.UpdatedAt = platformruntime.StatusFailed, run.Revision+1, now
	run.LeaseToken, run.LeaseUntil = "", time.Time{}
	if err := s.releaseSessionTx(tx, run); err != nil {
		return platformruntime.Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	return run, nil
}
