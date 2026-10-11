package notification

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/compensation"
)

const NotificationCompensationProvider = "platform.notification"

type CompensationPort struct {
	store           *SQLStore
	coordinator     compensation.EffectRegistry
	channel         RevocableChannel
	action, version string
}

// The controlled inbox is immediately usable by the normal notification
// Dispatcher. Its inverse additionally requires the exact coordinator lease
// and original message binding in the same SQL transaction.
func NewCompensatingInbox(ctx context.Context, db *sql.DB, coordinator compensation.EffectRegistry, action string) (*SQLInboxChannel, *CompensationPort, error) {
	if db == nil || coordinator == nil || (action != "withdraw" && action != "correct") {
		return nil, nil, compensation.ErrInvalid
	}
	p := &CompensationPort{store: NewSQLStore(db), coordinator: coordinator, action: action, version: InboxChannelVersion + "." + action}
	channel, err := NewSQLInboxChannel(ctx, db, p.guardReversalTx)
	if err != nil {
		return nil, nil, err
	}
	p.channel = channel
	return channel, p, nil
}
func (p *CompensationPort) Registration() compensation.Registration {
	return compensation.Registration{Provider: NotificationCompensationProvider, Version: p.version, Timeout: 5 * time.Second, Port: p}
}
func (p *CompensationPort) check(step compensation.Step) error {
	if p == nil || step.Validate() != nil || step.Provider != NotificationCompensationProvider || step.ProviderVersion != p.version || step.Kind != "notification" || (step.Tool != "notify.self" && step.Tool != "send_notification") {
		return compensation.ErrInvalid
	}
	return nil
}
func matchesNotificationStep(step compensation.Step, event Event) bool {
	s := step.Scope
	if step.Ref != event.ID || s.TenantID != event.TenantID || s.DepartmentID != event.DepartmentID || s.ApplicationID != event.ApplicationID {
		return false
	}
	for key, value := range map[string]string{"tool_name": step.Tool, "tool_call_id": step.CallID, "tool_fingerprint": step.Fingerprint, "run_id": s.RunID, "session_id": s.SessionID, "installation_id": s.InstallationID, "agent_version_id": s.AgentVersionID, "agent_id": s.AgentID, "agent_instance_id": s.AgentInstanceID, "principal_id": s.PrincipalID, "principal_type": s.PrincipalType, "trace_id": s.TraceID} {
		if event.Payload[key] != value {
			return false
		}
	}
	return true
}

// Called before EnqueueTx in the producer's SAME transaction. It leaves no
// orphan effect registration when the outbox transaction rolls back.
func (p *CompensationPort) RegisterAgentEffectTx(ctx context.Context, tx *sql.Tx, step compensation.Step, event Event) error {
	if err := p.check(step); err != nil {
		return err
	}
	if event.Validate() != nil || !matchesNotificationStep(step, event) {
		return compensation.ErrConflict
	}
	if _, err := AgentReversalBinding(event); err != nil {
		return err
	}
	return p.coordinator.RegisterTx(ctx, tx, step)
}
func (p *CompensationPort) requestTx(ctx context.Context, tx *sql.Tx, step compensation.Step) (ReversalRequest, bool, error) {
	if err := p.check(step); err != nil {
		return ReversalRequest{}, false, err
	}
	event, err := getEventTx(ctx, tx, step.Ref, false)
	if errors.Is(err, sql.ErrNoRows) {
		return ReversalRequest{}, false, nil
	}
	if err != nil {
		return ReversalRequest{}, false, err
	}
	if !matchesNotificationStep(step, event) {
		return ReversalRequest{}, false, compensation.ErrConflict
	}
	binding, err := AgentReversalBinding(event)
	if err != nil {
		return ReversalRequest{}, false, err
	}
	return ReversalRequest{Version: "notification-reversal/v1", Binding: binding, Key: step.CompensationKey(), Action: p.action}, true, nil
}
func (p *CompensationPort) guardReversalTx(ctx context.Context, tx *sql.Tx, request ReversalRequest) error {
	lease, err := compensation.CurrentLeaseFromContext(ctx)
	if err != nil {
		return err
	}
	if err = p.check(lease.Step); err != nil {
		return err
	}
	if err = p.coordinator.GuardLeaseTx(ctx, tx, lease); err != nil {
		return err
	}
	bound, found, err := p.requestTx(ctx, tx, lease.Step)
	if err != nil {
		return err
	}
	if !found || bound != request {
		return compensation.ErrConflict
	}
	return nil
}
func (p *CompensationPort) Lookup(ctx context.Context, step compensation.Step) (compensation.Receipt, bool, error) {
	if err := p.check(step); err != nil {
		return compensation.Receipt{}, false, err
	}
	tx, err := p.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return compensation.Receipt{}, false, err
	}
	defer tx.Rollback()
	r, found, err := p.requestTx(ctx, tx, step)
	if err != nil || !found {
		return compensation.Receipt{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return compensation.Receipt{}, false, err
	}
	proof, confirmed, err := p.channel.LookupReversal(ctx, r)
	if err != nil || !confirmed {
		return compensation.Receipt{}, false, err
	}
	if proof.Validate(r) != nil {
		return compensation.Receipt{}, false, ErrReversalUnconfirmed
	}
	return compensation.Receipt{Version: compensation.ContractVersion, StepDigest: step.Digest(), Key: step.CompensationKey(), Action: proof.Disposition, EvidenceDigest: proof.EvidenceDigest}, true, nil
}
func (p *CompensationPort) InspectOriginal(ctx context.Context, step compensation.Step) (compensation.OriginalEffect, error) {
	if err := p.check(step); err != nil {
		return compensation.OriginalEffect{}, err
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return compensation.OriginalEffect{}, err
	}
	defer tx.Rollback()
	if err = p.coordinator.GuardRegisteredStopTx(ctx, tx, step); err != nil {
		return compensation.OriginalEffect{}, err
	}
	request, found, err := p.requestTx(ctx, tx, step)
	if err != nil {
		return compensation.OriginalEffect{}, err
	}
	state := "no_effect"
	if found {
		state = "applied"
	}
	return compensation.OriginalEffect{StepDigest: step.Digest(), State: state, EvidenceDigest: reversalDigest([]any{"notification-outbox-effect/v1", step.Digest(), request, found})}, tx.Commit()
}
func (p *CompensationPort) Compensate(ctx context.Context, step compensation.Step) (compensation.Receipt, error) {
	if err := p.check(step); err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	lease, err := compensation.LeaseFromContext(ctx, step)
	if err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	defer tx.Rollback()
	if err = p.coordinator.GuardLeaseTx(ctx, tx, lease); err != nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, err)
	}
	request, found, err := p.requestTx(ctx, tx, step)
	if err != nil || !found {
		return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, compensation.ErrConflict, err)
	}
	if err = tx.Commit(); err != nil {
		return compensation.Receipt{}, err
	}
	proof, err := p.channel.Revoke(ctx, request)
	if err != nil {
		return compensation.Receipt{}, err
	}
	if proof.Validate(request) != nil {
		return compensation.Receipt{}, ErrReversalUnconfirmed
	}
	return compensation.Receipt{Version: compensation.ContractVersion, StepDigest: step.Digest(), Key: step.CompensationKey(), Action: proof.Disposition, EvidenceDigest: proof.EvidenceDigest}, nil
}

var _ compensation.Port = (*CompensationPort)(nil)
