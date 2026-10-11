package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// This background control never creates a capability or restores business
// permission. Missing facts/proof are errors, not invented stop confirmation.
type coordinatedStopReconciler struct {
	db        *sql.DB
	runs      *execution.SQLStore
	routes    *agentcoordination.SQLRouteStore
	audit     audit.TxRecorder
	route     agentRouteAuthority
	mu        sync.Mutex
	after     string
	waitAfter string
}

func (c *coordinatedStopReconciler) Reconcile(ctx context.Context, limit int) error {
	if c == nil || c.db == nil || c.runs == nil || c.routes == nil || c.audit == nil {
		return agentcoordination.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	childrenErr := c.reconcileChildren(ctx, limit)
	waitErr := c.reconcileWaitingGroups(ctx, limit)
	return errors.Join(childrenErr, waitErr)
}

func (c *coordinatedStopReconciler) reconcileChildren(ctx context.Context, limit int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	batch, err := c.routes.ChildLifecycleCandidates(ctx, c.after, limit)
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		c.after = ""
		return nil
	}
	var failures []error
	for _, candidate := range batch {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if err := c.stopOrphan(ctx, candidate); err != nil {
			failures = append(failures, err)
		}
		// Retry a failed record on the next sweep; do not starve other children.
		c.after = candidate.ChildRunID
	}
	return errors.Join(failures...)
}

func (c *coordinatedStopReconciler) stopOrphan(ctx context.Context, candidate agentcoordination.ChildLifecycleCandidate) error {
	initial, err := c.runs.GetContext(ctx, candidate.ChildRunID)
	if err != nil {
		return err
	}
	if initial.Scope.ParentRunID != candidate.ParentRunID {
		return agentcoordination.ErrDenied
	}
	// The retain decision is read-only. Holding the child FOR UPDATE across it
	// blocks that child's model admission for the whole proof.
	cancel, err := c.observeOrphan(ctx, candidate, initial)
	if err != nil || !cancel {
		return err
	}
	return c.cancelOrphan(ctx, candidate, initial)
}

func (c *coordinatedStopReconciler) observeOrphan(ctx context.Context, candidate agentcoordination.ChildLifecycleCandidate, initial platformruntime.Run) (bool, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if c.route.identity == nil || c.route.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return false, agentcoordination.ErrDenied
	}
	if err := lockBudgetAncestors(ctx, tx, c.runs, initial.Scope); err != nil {
		return false, err
	}
	parent, err := c.runs.BudgetRunTx(ctx, tx, candidate.ParentRunID)
	if err != nil {
		return false, err
	}
	// Do not share the child row across retention. That share blocks the
	// child's model-admission fence for the whole authorization proof.
	child, err := c.runs.BudgetRunReadTx(ctx, tx, candidate.ChildRunID)
	if err != nil {
		return false, err
	}
	if !sameBudgetOwner(initial.Scope, child.Scope) || c.routes.CheckRecordedChildEdgeTx(ctx, tx, parent.Scope, child.Scope, candidate.Depth) != nil {
		return false, agentcoordination.ErrDenied
	}
	ctx = withEpochMemo(ctx, tx)
	retain := (parent.Status == platformruntime.StatusRunning && parent.HasLease && parent.LeaseUntil.After(time.Now().UTC())) || c.route.canRetainWaitingChildTx(ctx, tx, parent, child, candidate.Depth)
	if !retain {
		// Cancel rechecks under the child FOR UPDATE. Rolling this read back
		// avoids keeping a reservation exclusive lock that the sync does not need.
		return true, nil
	}
	if _, err := c.routes.SyncChildLifecycleTx(ctx, tx, parent.Scope, child.Scope, candidate.Depth); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

func (c *coordinatedStopReconciler) cancelOrphan(ctx context.Context, candidate agentcoordination.ChildLifecycleCandidate, initial platformruntime.Run) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if c.route.identity == nil || c.route.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return agentcoordination.ErrDenied
	}
	if err := lockBudgetAncestors(ctx, tx, c.runs, initial.Scope); err != nil {
		return err
	}
	parent, err := c.runs.BudgetRunTx(ctx, tx, candidate.ParentRunID)
	if err != nil {
		return err
	}
	child, err := c.runs.BudgetRunForUpdateTx(ctx, tx, candidate.ChildRunID)
	if err != nil {
		return err
	}
	if !sameBudgetOwner(initial.Scope, child.Scope) || c.routes.CheckRecordedChildEdgeTx(ctx, tx, parent.Scope, child.Scope, candidate.Depth) != nil {
		return agentcoordination.ErrDenied
	}
	synced, err := c.routes.SyncChildLifecycleTx(ctx, tx, parent.Scope, child.Scope, candidate.Depth)
	if err != nil {
		return err
	}
	if synced.Terminal || (parent.Status == platformruntime.StatusRunning && parent.HasLease && parent.LeaseUntil.After(time.Now().UTC())) || c.route.canRetainWaitingChildTx(ctx, tx, parent, child, candidate.Depth) {
		return tx.Commit()
	}
	result, err := c.runs.BeginOrphanChildCancellationTx(ctx, tx, parent.Scope, child.Scope, candidate.Depth, child.Revision)
	if err != nil {
		return err
	}
	if result.Changed {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		event := audit.Event{ID: "child-stop-" + hex.EncodeToString(nonce[:]), TenantID: child.Scope.TenantID, DepartmentID: child.Scope.DepartmentID, ApplicationID: child.Scope.ApplicationID, ActorType: "system", ActorID: "execution.reconciler", TraceID: child.Scope.TraceID, AggregateType: "run", AggregateID: child.Scope.RunID, Action: "agent.child_parent_stop_requested", Outcome: "success", Summary: "recorded parent is inactive; durable stop intent only"}
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
			return err
		}
		if err := c.audit.RecordTx(tx, event); err != nil {
			return err
		}
	}
	return tx.Commit()
}
