package execution

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CheckTaskLeaseTx fences internal task writes in the caller's transaction.
// Composition must supply a transaction from the same database and separately
// check current IAM authority; a persisted authorization epoch is not live IAM.
// Both execution rows remain locked until the task write commits or rolls back.
func (s *SQLStore) CheckTaskLeaseTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, token string, revision uint64) error {
	if tx == nil || scope.ValidateTrusted() != nil || token == "" || revision == 0 {
		return platformruntime.ErrLeaseConflict
	}
	return s.checkExecutionLeaseTx(ctx, tx, scope, revision, func(actual string) bool { return actual == token }, false)
}

// CheckCapabilityLeaseTx fences business state writes using signed lease proof,
// without exposing the worker's raw lease token to business Agents.
func (s *SQLStore) CheckCapabilityLeaseTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, binding sharedkernel.ExecutionLeaseBinding) error {
	if tx == nil || scope.ValidateTrusted() != nil || binding.Revision == 0 || len(binding.TokenHash) != 64 {
		return platformruntime.ErrLeaseConflict
	}
	return s.checkExecutionLeaseTx(ctx, tx, scope, binding.Revision, func(actual string) bool {
		hash := sha256.Sum256([]byte(actual))
		return hmac.Equal([]byte(fmt.Sprintf("%x", hash)), []byte(binding.TokenHash))
	}, false)
}

// CheckCheckpointLeaseTx keeps execution and session mutation fenced with
// shared locks. The caller must separately serialize its checkpoint CAS and
// scope quota. Admission that mutates execution still uses the exclusive guard.
func (s *SQLStore) CheckCheckpointLeaseTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, binding sharedkernel.ExecutionLeaseBinding) error {
	return s.CheckCapabilityReadLeaseTx(ctx, tx, scope, binding)
}

// Current execution facts may share the Run/Session fence if the transaction
// never mutates these rows. Effects in other tables need their own serialization
// (for example, budget counters and invocation admission). The caller must not
// later upgrade this fence. Cancellation and lease replacement still acquire
// incompatible locks and wait for this transaction.
func (s *SQLStore) CheckCapabilityReadLeaseTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, binding sharedkernel.ExecutionLeaseBinding) error {
	if tx == nil || scope.ValidateTrusted() != nil || binding.Revision == 0 || len(binding.TokenHash) != 64 {
		return platformruntime.ErrLeaseConflict
	}
	return s.checkExecutionLeaseTx(ctx, tx, scope, binding.Revision, func(actual string) bool {
		hash := sha256.Sum256([]byte(actual))
		return hmac.Equal([]byte(fmt.Sprintf("%x", hash)), []byte(binding.TokenHash))
	}, true)
}

func (s *SQLStore) checkExecutionLeaseTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, revision uint64, tokenMatches func(string) bool, shared bool) error {
	// Advisory first keeps the normal lifecycle lock order. Row fences also
	// cover recovery paths that mutate these rows without an advisory, and
	// session ownership across Runs. Independent checkpoint writers share both
	// fences; only lifecycle/task mutation requires exclusive row ownership.
	if err := lockExecutionAdvisory(ctx, tx, scope.RunID, shared); err != nil {
		return err
	}
	lockClause := " FOR UPDATE"
	if shared {
		lockClause = " FOR SHARE"
	}
	var run platformruntime.Run
	var status string
	var until sql.NullTime
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,tenant_id,department_id,application_id,agent_instance_id,agent_id,principal_id,principal_type,installation_id,agent_version_id,session_id,authorization_epoch,trace_id,request_json,status,revision,lease_token,lease_until FROM platform_execution_run WHERE run_id=?`+lockClause), scope.RunID).Scan(
		&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.RequestJSON, &status, &run.Revision, &run.LeaseToken, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	if err != nil {
		return err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	if run.Scope != scope || status != string(platformruntime.StatusRunning) || run.Revision != revision || run.LeaseToken == "" || !tokenMatches(run.LeaseToken) || !until.Valid {
		return platformruntime.ErrLeaseConflict
	}
	var owner, sessionToken string
	var sessionUntil sql.NullTime
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token,lease_until FROM platform_execution_session_lease WHERE session_key=?`+lockClause), platformruntime.SessionExecutionKey(scope)).Scan(&owner, &sessionToken, &sessionUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	if err != nil {
		return err
	}
	// PostgreSQL CURRENT_TIMESTAMP freezes at transaction start. Sample the
	// database clock after lock acquisition so waiting cannot revive an old lease.
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if owner != scope.RunID || sessionToken != run.LeaseToken || !sessionUntil.Valid || !until.Time.After(now) || !sessionUntil.Time.After(now) {
		return platformruntime.ErrLeaseConflict
	}
	return nil
}
