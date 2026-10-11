package execution

import (
	"context"
	"database/sql"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildLifecycleFacts struct {
	Scope              sharedkernel.Scope
	Status             platformruntime.Status
	Revision           uint64
	RequestFingerprint string
	TerminalVerified   bool
}

// ChildLifecycleTx exposes only execution-owned lifecycle proof, never output,
// error payloads, lease tokens or a permission to resume/re-dispatch the child.
func (s *SQLStore) ChildLifecycleTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope) (ChildLifecycleFacts, error) {
	empty := ChildLifecycleFacts{}
	if s == nil || tx == nil || parent.ValidateTrusted() != nil || child.ValidateTrusted() != nil || child.ParentRunID != parent.RunID || child.RunID == parent.RunID || child.TenantID != parent.TenantID || child.DepartmentID != parent.DepartmentID || child.ApplicationID != parent.ApplicationID || child.PrincipalType != parent.PrincipalType || child.PrincipalID != parent.PrincipalID || child.SessionID != parent.SessionID {
		return empty, platformruntime.ErrInvalidRequest
	}
	// A live child must stay readable without a row lock. Sharing it here sits
	// behind the child's own admission fence for the rest of this transaction.
	run, err := s.BudgetRunReadTx(ctx, tx, child.RunID)
	if err != nil {
		return empty, err
	}
	if run.Scope != child {
		return empty, platformruntime.ErrInvalidRequest
	}
	result := ChildLifecycleFacts{Scope: run.Scope, Status: run.Status, Revision: run.Revision, RequestFingerprint: run.RequestFingerprint}
	var expectedEvent string
	switch run.Status {
	case platformruntime.StatusSucceeded:
		expectedEvent = "task_completed"
	case platformruntime.StatusFailed:
		expectedEvent = "task_failed"
	case platformruntime.StatusCancelled:
		expectedEvent = "task_cancelled"
	default:
		return result, nil
	}
	run, err = s.BudgetRunTx(ctx, tx, child.RunID)
	if err != nil {
		return empty, err
	}
	if run.Scope != child {
		return empty, platformruntime.ErrInvalidRequest
	}
	result = ChildLifecycleFacts{Scope: run.Scope, Status: run.Status, Revision: run.Revision, RequestFingerprint: run.RequestFingerprint}
	switch run.Status {
	case platformruntime.StatusSucceeded:
		expectedEvent = "task_completed"
	case platformruntime.StatusFailed:
		expectedEvent = "task_failed"
	case platformruntime.StatusCancelled:
		expectedEvent = "task_cancelled"
	default:
		return result, nil
	}
	var revision uint64
	var event string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), child.RunID).Scan(&revision, &event)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return empty, err
	}
	if revision != run.Revision || event != expectedEvent {
		return empty, platformruntime.ErrRevisionConflict
	}
	result.TerminalVerified = true
	return result, nil
}
