package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type CoordinatedCancellationFacts struct {
	Scope    sharedkernel.Scope
	Status   platformruntime.Status
	Revision uint64
	Changed  bool
}

// BeginCoordinatedChildCancellationTx records stop intent only. The composition
// must prove its recorded coordination edge and current parent authority first.
// No remote stop, lease release, output acknowledgement or cost release occurs.
func (s *SQLStore) BeginCoordinatedChildCancellationTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding, child sharedkernel.Scope, depth int, expected uint64) (CoordinatedCancellationFacts, error) {
	empty := CoordinatedCancellationFacts{}
	if s == nil || tx == nil || expected == 0 || expected > 1<<63-1 || depth < 1 || depth > 4 || parent.ValidateTrusted() != nil || child.ValidateTrusted() != nil || child.ParentRunID != parent.RunID || child.RunID == parent.RunID || child.TenantID != parent.TenantID || child.DepartmentID != parent.DepartmentID || child.ApplicationID != parent.ApplicationID || child.PrincipalType != parent.PrincipalType || child.PrincipalID != parent.PrincipalID || child.SessionID != parent.SessionID {
		return empty, platformruntime.ErrInvalidRequest
	}
	if err := s.CheckCapabilityLeaseTx(ctx, tx, parent, lease); err != nil {
		return empty, err
	}
	return s.beginRecordedChildStopTx(ctx, tx, parent, child, depth, expected, "PARENT_CHILD_CANCEL_REQUESTED")
}

// BeginOrphanChildCancellationTx is a stop-only reconciler Port. The caller
// must prove the recorded coordination edge. This module independently requires
// the real immediate parent to have ended, paused or lost its live lease.
func (s *SQLStore) BeginOrphanChildCancellationTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, expected uint64) (CoordinatedCancellationFacts, error) {
	if s == nil || tx == nil || parent.ValidateTrusted() != nil {
		return CoordinatedCancellationFacts{}, platformruntime.ErrInvalidRequest
	}
	current, err := s.BudgetRunTx(ctx, tx, parent.RunID)
	if err != nil {
		return CoordinatedCancellationFacts{}, err
	}
	if !sameCoordinatedOwner(current.Scope, parent) {
		return CoordinatedCancellationFacts{}, platformruntime.ErrInvalidRequest
	}
	if current.Status == platformruntime.StatusRunning && current.HasLease && current.LeaseUntil.After(time.Now().UTC()) {
		return CoordinatedCancellationFacts{}, platformruntime.ErrLeaseConflict
	}
	return s.beginRecordedChildStopTx(ctx, tx, current.Scope, child, depth, expected, "PARENT_EXECUTION_ENDED")
}

func sameCoordinatedOwner(a, b sharedkernel.Scope) bool {
	a.AuthorizationEpoch, a.TraceID = 0, ""
	b.AuthorizationEpoch, b.TraceID = 0, ""
	return a == b
}

func (s *SQLStore) beginRecordedChildStopTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, expected uint64, reason string) (CoordinatedCancellationFacts, error) {
	empty := CoordinatedCancellationFacts{}
	if tx == nil || expected == 0 || expected > 1<<63-1 || depth < 1 || depth > 4 || child.ValidateTrusted() != nil || child.ParentRunID != parent.RunID || child.RunID == parent.RunID || child.TenantID != parent.TenantID || child.DepartmentID != parent.DepartmentID || child.ApplicationID != parent.ApplicationID || child.PrincipalType != parent.PrincipalType || child.PrincipalID != parent.PrincipalID || child.SessionID != parent.SessionID {
		return empty, platformruntime.ErrInvalidRequest
	}
	var lockedRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), child.RunID).Scan(&lockedRevision); err != nil {
		return empty, err
	}
	// The row lock is already held. A second FOR SHARE deadlocks a waiter.
	facts, err := s.BudgetRunReadTx(ctx, tx, child.RunID)
	if err != nil {
		return empty, err
	}
	if facts.Scope != child || facts.Revision != lockedRevision {
		return empty, platformruntime.ErrInvalidRequest
	}
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(facts.RequestJSON))
	decoder.UseNumber()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.ProtocolVersion != contract.ProtocolVersion || command.Scope.RunID != child.RunID || command.Scope.ParentRunID != parent.RunID || command.Scope.DelegationDepth != uint32(depth) || command.Operation != "run" {
		return empty, platformruntime.ErrInvalidRequest
	}
	c := command.Scope
	if c.TenantID != child.TenantID || c.DepartmentID != child.DepartmentID || c.ApplicationID != child.ApplicationID || c.PrincipalType != child.PrincipalType || c.PrincipalID != child.PrincipalID || c.SessionID != child.SessionID || c.AgentID != child.AgentID || c.AgentInstanceID != child.AgentInstanceID || c.InstallationID != child.InstallationID || c.AgentVersionID != child.AgentVersionID {
		return empty, platformruntime.ErrInvalidRequest
	}
	result := CoordinatedCancellationFacts{Scope: child, Status: facts.Status, Revision: facts.Revision}
	switch facts.Status {
	case platformruntime.StatusCancelling, platformruntime.StatusRecovering, platformruntime.StatusCancelled, platformruntime.StatusSucceeded, platformruntime.StatusFailed:
		// Stopping/terminal replay cannot start a new execution or erase outcome.
		return result, nil
	case platformruntime.StatusAccepted, platformruntime.StatusRunning, platformruntime.StatusWaiting:
	default:
		return empty, platformruntime.ErrInvalidTransition
	}
	if expected != facts.Revision {
		// The current facts were read while holding the child Run row lock. Keep
		// them available to the stop-only caller so it can return a narrow CAS
		// hint after it has verified the recorded route and proof. This is not a
		// result/history read and does not weaken the expected-revision check.
		return result, platformruntime.ErrRevisionConflict
	}
	changed, err := s.beginCancellationTx(ctx, tx, platformruntime.Run{ID: child.RunID, Scope: child, Status: facts.Status, Revision: facts.Revision}, reason)
	if err != nil {
		return empty, err
	}
	result.Status, result.Revision, result.Changed = changed.Status, changed.Revision, true
	return result, nil
}
