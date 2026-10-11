package execution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) claimSessionTx(tx *sql.Tx, run platformruntime.Run, token string, now, until time.Time) error {
	key := platformruntime.SessionExecutionKey(run.Scope)
	if _, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_execution_session_lease (session_key,run_id,lease_token,lease_until) VALUES (?,?,'',NULL) ON CONFLICT (session_key) DO UPDATE SET session_key=EXCLUDED.session_key`), key, run.ID); err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRow(sqlutil.Bind(`SELECT run_id FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), key).Scan(&owner); err != nil {
		return err
	}
	// The locked reservation serializes competing Runs; waiting remains a reservation.
	// 锁定持久化会话归属后检查 FIFO；等待审核仍占有 Checkpoint，禁止后续 Run 覆盖。
	var first string
	err := tx.QueryRow(sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE tenant_id=? AND department_id=? AND application_id=? AND installation_id=? AND agent_instance_id=? AND agent_id=? AND principal_type=? AND principal_id=? AND session_id=? AND agent_version_id=? AND status IN ('accepted','running','waiting','cancelling','recovering') ORDER BY created_at,run_id LIMIT 1`), run.Scope.TenantID, run.Scope.DepartmentID, run.Scope.ApplicationID, run.Scope.InstallationID, run.Scope.AgentInstanceID, run.Scope.AgentID, run.Scope.PrincipalType, run.Scope.PrincipalID, run.Scope.SessionID, run.Scope.AgentVersionID).Scan(&first)
	if err != nil {
		return err
	}
	if first != run.ID {
		return platformruntime.ErrLeaseConflict
	}
	if owner != run.ID {
		var status string
		err = tx.QueryRow(sqlutil.Bind(`SELECT status FROM platform_execution_run WHERE run_id=?`), owner).Scan(&status)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && (status == "accepted" || status == "running" || status == "waiting" || status == "cancelling" || status == "recovering") {
			return platformruntime.ErrLeaseConflict
		}
	}
	_, err = tx.Exec(sqlutil.Bind(`UPDATE platform_execution_session_lease SET run_id=?,lease_token=?,lease_until=? WHERE session_key=?`), run.ID, token, until, key)
	return err
}

func (s *SQLStore) releaseSessionTx(tx *sql.Tx, run platformruntime.Run) error {
	key := platformruntime.SessionExecutionKey(run.Scope)
	if run.Status == platformruntime.StatusWaiting {
		_, err := tx.Exec(sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_token='',lease_until=NULL WHERE session_key=? AND run_id=?`), key, run.ID)
		return err
	}
	if run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled {
		_, err := tx.Exec(sqlutil.Bind(`DELETE FROM platform_execution_session_lease WHERE session_key=? AND run_id=?`), key, run.ID)
		return err
	}
	return nil
}

func (s *SQLStore) CheckSessionLease(run platformruntime.Run, now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var matched int
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_execution_session_lease WHERE session_key=? AND run_id=? AND lease_token=? AND lease_until>?`), platformruntime.SessionExecutionKey(run.Scope), run.ID, run.LeaseToken, now).Scan(&matched)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	return err
}
