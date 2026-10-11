package execution

import (
	"context"
	"encoding/json"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// BeginRecovery fences an expired owner without releasing its checkpoint lock.
// 原子隔离过期执行者，但旧图停止确认之前不能释放 Checkpoint 归属。
func (s *SQLStore) BeginRecovery(id string, expected uint64, now time.Time) (platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	run, err := s.GetContext(ctx, id)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if run.Status != platformruntime.StatusRunning || run.Revision != expected || run.LeaseToken == "" || run.LeaseUntil.After(now) {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='recovering',revision=revision+1,updated_at=? WHERE run_id=? AND status='running' AND revision=? AND lease_token=? AND (lease_until IS NULL OR lease_until<=?)`), now, id, expected, run.LeaseToken, now)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return platformruntime.Run{}, err
	} else if affected != 1 {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	payload, err := json.Marshal(map[string]any{"revision": expected + 1, "code": "EXECUTION_LEASE_EXPIRED"})
	if err != nil {
		return platformruntime.Run{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), id, "recovery_stop_requested", payload, now); err != nil {
		return platformruntime.Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	run.Status = platformruntime.StatusRecovering
	run.Revision++
	run.UpdatedAt = now
	return run, nil
}

// CompleteRecovery keeps the original request and resume input in one transaction.
// 旧世代停止后保留原请求和恢复输入；归属仍是原 Run，不创建取消结果。
func (s *SQLStore) CompleteRecovery(id string, expected uint64) (platformruntime.Run, error) {
	return s.completeRecoveryWithEvidence(id, expected, nil)
}

func (s *SQLStore) CompleteRecoveryWithStopEvidence(id string, expected uint64, proof StopEvidence) (platformruntime.Run, error) {
	if proof.Source != "runtime-process-stop/v1" || len(proof.Digest) != 64 || len(proof.RuntimeID) != 64 {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	return s.completeRecoveryWithEvidence(id, expected, &proof)
}

func (s *SQLStore) completeRecoveryWithEvidence(id string, expected uint64, proof *StopEvidence) (platformruntime.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return platformruntime.Run{}, err
	}
	defer tx.Rollback()
	run, err := readExecutionRun(ctx, tx, id, " FOR UPDATE")
	if err != nil {
		return platformruntime.Run{}, err
	}
	if run.Status != platformruntime.StatusRecovering || run.Revision != expected {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	stopPayload := map[string]any{"revision": expected + 1}
	if run.AgentEndpoint == "" {
		if proof != nil {
			return platformruntime.Run{}, platformruntime.ErrInvalidRequest
		}
		reference, err := internalRecoveryReferenceTx(ctx, tx, run)
		if err != nil {
			return platformruntime.Run{}, err
		}
		stopPayload["internal_recovery_reference"] = reference
	} else {
		if s.recoveryDescendants != nil {
			if err := s.recoveryDescendants(ctx, tx, run.Scope); err != nil {
				return platformruntime.Run{}, err
			}
		}
		reference, err := recoveryStopReferenceTx(ctx, tx, run, proof)
		if err != nil {
			return platformruntime.Run{}, err
		}
		if s.recoveryCheckpoints != nil {
			checkpoints, err := s.recoveryCheckpoints(ctx, tx, run.Scope, reference.StoppedRevision)
			if err != nil {
				if s.recoveryStateLost != nil && s.recoveryStateLost(err) {
					return s.failStoppedRecoveryTx(ctx, tx, run, reference, proof)
				}
				return platformruntime.Run{}, err
			}
			reference.Checkpoints = checkpoints
			if len(checkpoints) == 0 || !reference.valid() {
				return platformruntime.Run{}, platformruntime.ErrInvalidRequest
			}
		}
		stopPayload["recovery_reference"] = reference
	}
	if proof != nil {
		if run.LeaseToken == "" || expected == 0 {
			return platformruntime.Run{}, platformruntime.ErrInvalidTransition
		}
		payload, err := json.Marshal(proof)
		if err != nil {
			return platformruntime.Run{}, err
		}
		if _, err = s.dbProofEvent(tx, run.ID, payload); err != nil {
			return platformruntime.Run{}, err
		}
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='running',revision=revision+1,lease_token='',lease_until=NULL,updated_at=? WHERE run_id=? AND status='recovering' AND revision=?`), now, id, expected)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return platformruntime.Run{}, err
	} else if affected != 1 {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	result, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_token='',lease_until=NULL WHERE session_key=? AND run_id=?`), platformruntime.SessionExecutionKey(run.Scope), id)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return platformruntime.Run{}, err
	} else if affected != 1 {
		return platformruntime.Run{}, platformruntime.ErrLeaseConflict
	}
	payload, err := json.Marshal(stopPayload)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`), id, "recovery_stop_confirmed", payload, now); err != nil {
		return platformruntime.Run{}, err
	}
	if err := tx.Commit(); err != nil {
		return platformruntime.Run{}, err
	}
	run.Status = platformruntime.StatusRunning
	run.Revision++
	run.LeaseToken = ""
	run.LeaseUntil = time.Time{}
	run.UpdatedAt = now
	return run, nil
}
