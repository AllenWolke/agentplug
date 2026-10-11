package main

import (
	"context"
	"database/sql"
	"log"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

// Each repository supplies only its own domain owners. Public agentplug has no
// regulatory import; the interview composition adds that owner through a port.
type cancellationDomainInstaller func(*compensation.LocalEffectLedger, *cancellationEffects) ([]compensation.Registration, error)

type cancellationSetup struct {
	runs          *execution.SQLStore
	execution     *execution.Module
	routes        *agentcoordination.SQLRouteStore
	capabilities  *capability.Module
	tools         *capability.SQLToolInvocationStore
	memory        *capability.SQLMemoryStore
	tree          *usagecost.SQLRunTreeBudgetStore
	iam           *identity.SQLStore
	evaluation    *evaluationExecutionAuthority
	outbox        *notification.SQLStore
	notifications *notification.Module
	channel       *agentNotificationChannel
	audit         audit.TxRecorder
	domain        cancellationDomainInstaller
}

func (s cancellationSetup) bindTransaction(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) context.Context {
	ctx = withEpochMemo(ctx, tx)
	ctx = withBudgetAncestryTransaction(ctx, tx)
	return capability.WithSQLSkillTransaction(ctx, s.runs.DB(), tx, scope)
}

func (s cancellationSetup) guardForward(ctx context.Context, tx *sql.Tx, step compensation.Step) error {
	ctx = s.bindTransaction(ctx, tx, step.Scope)
	if err := s.iam.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	if err := lockCheckpointAncestors(ctx, tx, s.runs, s.evaluation, step.Scope); err != nil {
		return err
	}
	if step.Kind == "index" {
		run, err := s.runs.GetContext(ctx, step.Scope.RunID)
		if err != nil || run.Scope != step.Scope {
			return compensation.ErrConflict
		}
		target, _, _, err := indexRunParameters(run)
		if err != nil {
			return err
		}
		p := knowledgePersistence{db: s.runs.DB(), iam: s.iam, execution: s.runs, audit: s.audit}
		if err := p.authorize(ctx, tx, step.Scope, target); err != nil {
			return err
		}
		lease, found := sharedkernel.ExecutionLeaseFromContext(ctx)
		if !found {
			return compensation.ErrUnavailable
		}
		return s.runs.CheckCapabilityLeaseTx(ctx, tx, step.Scope, lease)
	}
	return s.tree.CheckRuntimeAdmissionTx(ctx, tx, step.Scope)
}

// configure performs read-only schema checks and startup composition. Applying
// DDL, changing providers, or inventing historical inverse registrations is
// deliberately outside this function.
func (s cancellationSetup) configure(ctx context.Context) (*knowledge.IndexCompensation, error) {
	if ctx == nil || s.runs == nil || s.execution == nil || s.routes == nil || s.capabilities == nil || s.tools == nil || s.memory == nil || s.tree == nil || s.iam == nil || s.outbox == nil || s.channel == nil || s.audit == nil {
		return nil, compensation.ErrUnavailable
	}
	effects := &cancellationEffects{routes: s.routes, tools: s.tools, capabilities: s.capabilities, bindings: make(map[string]cancellationToolBinding)}
	version := notification.InboxChannelVersion + ".withdraw"
	for _, name := range []string{"notify.self", "send_notification"} {
		descriptor, found := s.capabilities.RuntimeToolDescriptor(name)
		if !found {
			return nil, compensation.ErrUnavailable
		}
		effects.bindings[name] = cancellationToolBinding{descriptor: descriptor, step: func(q capability.ToolReceiptQuery) (compensation.Step, error) {
			return notificationCancellationStep(q, version)
		}}
	}
	if err := s.runs.SetCancellationOutcomeFence(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
		_, err := effects.stoppedScopes(ctx, tx, scope)
		return err
	}); err != nil {
		return nil, err
	}
	ledger, err := s.runs.EnableCancellationCompensation(ctx, effects.ports(s.guardForward))
	if err != nil {
		return nil, err
	}
	effects.ledger = ledger
	local, err := compensation.NewLocalEffectLedger(ctx, s.runs.DB(), ledger)
	if err != nil {
		return nil, err
	}
	var registrations []compensation.Registration
	runtimeOwners, err := s.capabilities.RuntimeCancellationBindings(ledger, s.tools)
	if err != nil {
		return nil, err
	}
	for _, owner := range runtimeOwners {
		registrations = append(registrations, owner.Registration)
		for _, name := range owner.Tools {
			descriptor, found := s.capabilities.RuntimeToolDescriptor(name)
			if !found || effects.bindings[name].step != nil {
				return nil, compensation.ErrConflict
			}
			effects.bindings[name] = cancellationToolBinding{descriptor: descriptor, step: owner.Step}
		}
	}
	if s.domain != nil {
		extra, err := s.domain(local, effects)
		if err != nil {
			return nil, err
		}
		registrations = append(registrations, extra...)
	}
	if err := s.memory.SetCancellationCompensation(local, func(_ context.Context, _ *sql.Tx, scope sharedkernel.Scope) (sharedkernel.Scope, error) {
		return scope, nil
	}); err != nil {
		return nil, err
	}
	if err := s.memory.SetCancellationTransactionContext(s.bindTransaction); err != nil {
		return nil, err
	}
	registration, err := s.memory.MemoryCompensationRegistration()
	if err != nil {
		return nil, err
	}
	registrations = append(registrations, registration)
	persistence := knowledgePersistence{db: s.runs.DB(), iam: s.iam, execution: s.runs, audit: s.audit}
	index, err := knowledge.NewIndexCompensation(local, func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, target knowledge.ProjectionScope, step string) error {
		// Stopping is a control operation and survives revocation. No new source
		// grant is acquired; the owner CAS and inverse lease guard the change.
		return persistence.record(tx, scope, target, "knowledge.index.compensated", map[string]any{"step_id": step, "compensation_version": compensation.ContractVersion})
	})
	if err != nil {
		return nil, err
	}
	registration, err = index.Registration()
	if err != nil {
		return nil, err
	}
	registrations = append(registrations, registration)
	inbox, notificationOwner, err := notification.NewCompensatingInbox(ctx, s.runs.DB(), ledger, "withdraw")
	if err != nil {
		return nil, err
	}
	if err := s.channel.installInbox(inbox); err != nil {
		return nil, err
	}
	registrations = append(registrations, notificationOwner.Registration())
	s.channel.mu.Lock()
	s.channel.redrive, s.channel.redriveGuard = notificationOwner, func(ctx context.Context, tx *sql.Tx, step compensation.Step) error {
		ctx = s.bindTransaction(ctx, tx, step.Scope)
		if err := s.iam.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return err
		}
		// Initial transport redrive supports root business Runs only. Delegated
		// or evaluation children need their own current edge/parent admission.
		if step.Scope.ParentRunID != "" {
			return compensation.ErrUnavailable
		}
		facts, err := s.runs.BudgetRunForUpdateTx(ctx, tx, step.Scope.RunID)
		if err != nil || facts.Scope != step.Scope || (facts.Status != platformruntime.StatusSucceeded && facts.Status != platformruntime.StatusRunning) {
			return compensation.ErrPending
		}
		epoch, err := s.iam.CurrentAuthorizationEpoch(ctx, step.Scope, "run")
		if err != nil || epoch != step.Scope.AuthorizationEpoch {
			return identity.ErrPermissionDenied
		}
		return nil
	}
	s.channel.mu.Unlock()
	if s.notifications == nil {
		return nil, compensation.ErrUnavailable
	}
	access := deadLetterAuthority{iam: s.iam, outbox: s.outbox, audit: s.audit}
	if err := s.notifications.SetRecipientInbox(inbox, access.ResolveBrowser, access.AuthorizeInbox); err != nil {
		return nil, err
	}
	s.capabilities.SetNotificationToolPort(platformNotificationToolAdapter{outbox: s.outbox, db: s.runs.DB(), guard: s.tools, compensation: notificationOwner, compensationVersion: version})
	if err := s.tools.SetCancellationRegistrar(func(ctx context.Context, tx *sql.Tx, q capability.ToolReceiptQuery) error {
		step, write, err := effects.toolStep(q)
		if err != nil || !write {
			return err
		}
		ctx = s.bindTransaction(ctx, tx, q.Scope)
		return ledger.RegisterTx(ctx, tx, step)
	}); err != nil {
		return nil, err
	}
	// Only model/fee settlement precedes the stop proof. The SQL cancellation
	// fence then checks all exact tool registrations and stopped descendants.
	if err := s.execution.SetCancellationStopQuiescence(s.capabilities.CheckTaskModelQuiescence); err != nil {
		return nil, err
	}
	s.runs.SetAgentGroupStopBarrier(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, _ contract.AgentGroupHandoff) error {
		_, err := effects.stoppedScopes(ctx, tx, scope)
		return err
	})
	engine, err := compensation.NewEngine(ledger, "platform-compensation-worker", registrations...)
	if err != nil {
		return nil, err
	}
	if err := s.execution.SetCancellationCompensationWorker(engine, ledger, func(stats compensation.SweepStats, unavailable bool) {
		// Bounded counters only; no credentials, payloads or provider errors.
		if stats.Handled > 0 || stats.Completed > 0 || stats.Failed > 0 || unavailable {
			log.Printf("cancellation_compensation visited=%d handled=%d completed=%d pending=%d failed=%d unavailable=%t", stats.Visited, stats.Handled, stats.Completed, stats.Pending, stats.Failed, unavailable)
		}
	}); err != nil {
		return nil, err
	}
	return index, nil
}
