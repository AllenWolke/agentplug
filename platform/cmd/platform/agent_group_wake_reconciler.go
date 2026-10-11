package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func (c *coordinatedStopReconciler) reconcileWaitingGroups(ctx context.Context, limit int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ids, err := c.runs.AgentGroupWaitingCandidates(ctx, c.waitAfter, limit)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		c.waitAfter = ""
		return nil
	}
	var failures []error
	for _, id := range ids {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		if err := c.wakeGroup(ctx, id); err != nil {
			failures = append(failures, err)
		}
		c.waitAfter = id
	}
	return errors.Join(failures...)
}

// This creates no capability and never invokes an Agent. Current permissions,
// pinned State and actual child terminal proofs precede a durable queue CAS.
// The poll that finds a still-running child takes only share locks. Holding
// the parent FOR UPDATE across that read starves the child's ancestor share
// lock for the whole sweep; that wait is not a budget or permission denial.
func (c *coordinatedStopReconciler) wakeGroup(ctx context.Context, id string) error {
	initial, err := c.runs.BudgetRunContext(ctx, id)
	if err != nil {
		return err
	}
	if initial.Status != platformruntime.StatusWaiting {
		return nil
	}
	mutate, err := c.reconcileOneWaitingGroup(ctx, initial, false)
	if err != nil || !mutate {
		return err
	}
	_, err = c.reconcileOneWaitingGroup(ctx, initial, true)
	return err
}

func (c *coordinatedStopReconciler) reconcileOneWaitingGroup(ctx context.Context, initial execution.BudgetRunFacts, exclusive bool) (bool, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	ctx = withEpochMemo(ctx, tx)
	if c.route.identity == nil || c.route.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return false, agentcoordination.ErrDenied
	}
	if err := lockBudgetAncestors(ctx, tx, c.runs, initial.Scope); err != nil {
		return false, err
	}
	var parent execution.BudgetRunFacts
	if exclusive {
		parent, err = c.runs.BudgetRunForUpdateTx(ctx, tx, initial.Scope.RunID)
	} else {
		parent, err = c.runs.BudgetRunTx(ctx, tx, initial.Scope.RunID)
	}
	if err != nil {
		return false, err
	}
	if parent.Status != platformruntime.StatusWaiting {
		return false, nil
	}
	if parent.Scope != initial.Scope {
		return false, agentcoordination.ErrDenied
	}
	stopOrResume := func(reason string) (bool, error) {
		if !exclusive {
			return true, nil
		}
		return false, c.stopWaitingGroupTx(ctx, tx, parent, reason)
	}
	ref, err := c.runs.CurrentAgentGroupWaitTx(ctx, tx, parent.Scope)
	if err != nil {
		if errors.Is(err, capability.ErrStateContinuityLost) || errors.Is(err, capability.ErrStateUnavailable) || errors.Is(err, platformruntime.ErrInvalidTransition) {
			return stopOrResume("GROUP_STATE_CONTINUITY_LOST")
		}
		return false, err
	}
	command, policy, err := budgetRunPolicy(ctx, tx, parent)
	if err != nil {
		return false, err
	}
	delegation := policy.Runtime.Delegation
	if delegation == nil || delegation.Validate() != nil {
		return stopOrResume("GROUP_AUTHORIZATION_DENIED")
	}
	if (coordinatedAncestryGuard{route: c.route}).CheckWaitingTx(ctx, tx, parent.Scope) != nil {
		return stopOrResume("GROUP_AUTHORIZATION_DENIED")
	}
	authorize := func() error {
		actions := []string{"agent.delegate"}
		if parent.Scope.ParentRunID == "" {
			actions = append(actions, "run")
		}
		for _, action := range actions {
			if c.route.resources.AuthorizeCapabilityResource(ctx, parent.Scope, capability.CapabilityResourceAccess{Action: action, ResourceType: "agent_installation", ResourceID: parent.Scope.InstallationID}) != nil {
				return agentcoordination.ErrDenied
			}
		}
		return nil
	}
	if err := authorize(); err != nil {
		return stopOrResume("GROUP_AUTHORIZATION_DENIED")
	}
	facts := agentcoordination.ParentFacts{Scope: parent.Scope, PolicyHash: policy.Hash, Policy: delegation, Depth: int(command.Scope.DelegationDepth), Active: true}
	var terminal bool
	if exclusive {
		terminal, err = c.routes.WaitingGroupTerminalTx(ctx, tx, facts, ref.Handoff)
	} else {
		terminal, err = c.routes.WaitingGroupTerminalShareTx(ctx, tx, facts, ref.Handoff)
	}
	if err != nil {
		if errors.Is(err, agentcoordination.ErrDenied) {
			return stopOrResume("GROUP_AUTHORIZATION_DENIED")
		}
		return false, err
	}
	if !terminal {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if !exclusive {
		return true, nil
	}
	if err := authorize(); err != nil {
		return stopOrResume("GROUP_AUTHORIZATION_DENIED")
	}
	revision, err := c.runs.QueueAgentGroupResumeTx(ctx, tx, parent.Scope, parent.Revision)
	if err != nil {
		return false, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	event := audit.Event{ID: "group-wake-" + hex.EncodeToString(nonce[:]), TenantID: parent.Scope.TenantID, DepartmentID: parent.Scope.DepartmentID, ApplicationID: parent.Scope.ApplicationID, ActorType: "system", ActorID: "execution.reconciler", TraceID: parent.Scope.TraceID, AggregateType: "run", AggregateID: parent.Scope.RunID, Action: "agent.group_resume_queued", Outcome: "success", Summary: fmt.Sprintf("revision=%d children=%d", revision, len(ref.Handoff.ChildKeys))}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return false, err
	}
	if err := c.audit.RecordTx(tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}

func (c *coordinatedStopReconciler) stopWaitingGroupTx(ctx context.Context, tx *sql.Tx, parent execution.BudgetRunFacts, reason string) error {
	stopped, err := c.runs.BeginAgentGroupWaitCancellationTx(ctx, tx, parent.Scope, parent.Revision, reason)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	event := audit.Event{ID: "group-stop-" + hex.EncodeToString(nonce[:]), TenantID: parent.Scope.TenantID, DepartmentID: parent.Scope.DepartmentID, ApplicationID: parent.Scope.ApplicationID, ActorType: "system", ActorID: "execution.reconciler", TraceID: parent.Scope.TraceID, AggregateType: "run", AggregateID: parent.Scope.RunID, Action: "agent.group_stop_requested", Outcome: "success", Summary: fmt.Sprintf("reason=%s revision=%d", reason, stopped.Revision)}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return err
	}
	if err := c.audit.RecordTx(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
