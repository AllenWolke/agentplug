package execution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// BudgetRunFacts is an accounting composition projection, never a browser DTO.
// It excludes endpoint, output and lease secrets. RequestJSON proves immutable
// published policy and delegation depth; consumers must not expose it to users.
type BudgetRunFacts struct {
	Scope              sharedkernel.Scope
	Status             platformruntime.Status
	Revision           uint64
	RequestJSON        []byte
	RequestFingerprint string
	AgentEndpoint      string
	HasLease           bool
	LeaseUntil         time.Time
}

// BudgetRunForUpdateTx locks before reading its projection. Stop-only control
// paths must not take SHARE and then race another controller's lock upgrade.
func (s *SQLStore) BudgetRunForUpdateTx(ctx context.Context, tx *sql.Tx, id string) (BudgetRunFacts, error) {
	if s == nil || tx == nil || id == "" || len(id) > 128 {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	return s.readBudgetRun(ctx, tx, id, " FOR UPDATE")
}

type budgetRunQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// BudgetRunContext is a non-locking, non-secret control projection. Live
// ancestry callbacks can run inside a transaction already owning the actor
// UPDATE fence, and must not deadlock by locking that actor again elsewhere.
func (s *SQLStore) BudgetRunContext(ctx context.Context, id string) (BudgetRunFacts, error) {
	if s == nil || s.db == nil {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	return s.readBudgetRun(ctx, s.db, id, "")
}

func (s *SQLStore) BudgetRunTx(ctx context.Context, tx *sql.Tx, id string) (BudgetRunFacts, error) {
	if s == nil || tx == nil || id == "" || len(id) > 128 {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	return s.readBudgetRun(ctx, tx, id, " FOR SHARE")
}

// BudgetRunReadTx reads the same projection inside the caller transaction
// without a row lock. Live ancestry uses it only for the actor row: another
// transaction may already hold that row FOR UPDATE, and FOR SHARE here deadlocks
// with a controller that locked the actor before the reservation. Callers still
// compare every scope, edge and epoch; this does not authorize by itself.
func (s *SQLStore) BudgetRunReadTx(ctx context.Context, tx *sql.Tx, id string) (BudgetRunFacts, error) {
	if s == nil || tx == nil || id == "" || len(id) > 128 {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	return s.readBudgetRun(ctx, tx, id, "")
}

func (s *SQLStore) readBudgetRun(ctx context.Context, queryer budgetRunQueryer, id, lock string) (BudgetRunFacts, error) {
	if queryer == nil || id == "" || len(id) > 128 || (lock != "" && lock != " FOR SHARE" && lock != " FOR UPDATE") {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	var run platformruntime.Run
	var status string
	var revision uint64
	var hasLease bool
	var fingerprint string
	var factsEndpoint string
	var leaseUntil sql.NullTime
	err := queryer.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,tenant_id,department_id,application_id,agent_instance_id,agent_id,principal_id,principal_type,installation_id,agent_version_id,session_id,authorization_epoch,trace_id,request_json,status,revision,(lease_token<>''),lease_until,fingerprint,agent_endpoint FROM platform_execution_run WHERE run_id=?`+lock), id).Scan(&run.ID, &run.Scope.TenantID, &run.Scope.DepartmentID, &run.Scope.ApplicationID, &run.Scope.AgentInstanceID, &run.Scope.AgentID, &run.Scope.PrincipalID, &run.Scope.PrincipalType, &run.Scope.InstallationID, &run.Scope.AgentVersionID, &run.Scope.SessionID, &run.Scope.AuthorizationEpoch, &run.Scope.TraceID, &run.RequestJSON, &status, &revision, &hasLease, &leaseUntil, &fingerprint, &factsEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return BudgetRunFacts{}, platformruntime.ErrRunNotFound
	}
	if err != nil {
		return BudgetRunFacts{}, err
	}
	run.Scope.RunID = run.ID
	restoreParentRunID(&run)
	if run.Scope.ValidateTrusted() != nil || len(run.RequestJSON) == 0 || len(run.RequestJSON) > 1<<20 {
		return BudgetRunFacts{}, platformruntime.ErrInvalidRequest
	}
	return BudgetRunFacts{Scope: run.Scope, Status: platformruntime.Status(status), Revision: revision, RequestJSON: run.RequestJSON, RequestFingerprint: fingerprint, AgentEndpoint: factsEndpoint, HasLease: hasLease, LeaseUntil: leaseUntil.Time}, nil
}
