package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/platform/internal/compensation"
)

const codeCancellationProvider = "platform.code.sandbox"

// Isolated code has no network, persistent host files or business credential.
// Its inverse is positive proof of container removal, not re-executing code.
// An absent/UNKNOWN receipt cannot prove no effect or block late execution.
type codeCancellationPort struct {
	provider *CodeToolProvider
	ledger   compensation.EffectLedger
	tools    *SQLToolInvocationStore
	version  string
}

func (p *CodeToolProvider) cancellationVersion() (string, error) {
	if p == nil || len(p.bindings) == 0 {
		return "", compensation.ErrUnavailable
	}
	// Include every immutable scoped controller/profile/resource binding. Only
	// the digest is persisted; private controller origins never enter reports.
	bindings := make([]string, 0, len(p.bindings))
	for key, b := range p.bindings {
		raw, err := json.Marshal(struct {
			Tool, Tenant, Application, Agent, Endpoint, Controller, Profile, Language string
			Limits                                                                    protocol.Limits
		}{key.tool, key.tenant, key.application, key.agent, b.binding.Endpoint, b.binding.ControllerID, b.binding.ProfileID, b.binding.Language, b.binding.Limits})
		if err != nil {
			return "", compensation.ErrInvalid
		}
		bindings = append(bindings, string(raw))
	}
	sort.Strings(bindings)
	raw, _ := json.Marshal(bindings)
	digest := sha256.Sum256(raw)
	return "sandbox-cleanup.v1." + hex.EncodeToString(digest[:]), nil
}

func (p *CodeToolProvider) cancellationStep(q ToolReceiptQuery, version string) (compensation.Step, error) {
	if p == nil || q.Scope.ValidateTrusted() != nil || !codeIdentifier(q.CallID) || !auditRuntimeDigest(q.Fingerprint) {
		return compensation.Step{}, compensation.ErrInvalid
	}
	if _, found := p.scopedTool(q.Scope, q.Name); !found {
		return compensation.Step{}, compensation.ErrConflict
	}
	ref := sha256.Sum256([]byte(ToolReceiptScopeHash(q.Scope) + "\x00" + q.CallID))
	step := compensation.Step{Root: q.Scope, Scope: q.Scope, ID: compensation.StepID(q.Scope, "tool", q.CallID), Kind: "tool", Tool: q.Name, Provider: codeCancellationProvider, ProviderVersion: version, CallID: q.CallID, Fingerprint: q.Fingerprint, Ref: hex.EncodeToString(ref[:])}
	return step, step.Validate()
}

func (p *CodeToolProvider) CancellationBinding(ledger compensation.EffectLedger, tools *SQLToolInvocationStore) (RuntimeCancellationBinding, error) {
	if ledger == nil || tools == nil {
		return RuntimeCancellationBinding{}, compensation.ErrUnavailable
	}
	version, err := p.cancellationVersion()
	if err != nil {
		return RuntimeCancellationBinding{}, err
	}
	port := &codeCancellationPort{provider: p, ledger: ledger, tools: tools, version: version}
	names := p.RegisteredTools()
	sort.Strings(names)
	return RuntimeCancellationBinding{Registration: compensation.Registration{Provider: codeCancellationProvider, Version: version, Timeout: 10 * time.Second, Port: port}, Tools: names, Step: func(q ToolReceiptQuery) (compensation.Step, error) { return p.cancellationStep(q, version) }}, nil
}

func (p *codeCancellationPort) cleanup(ctx context.Context, step compensation.Step) (compensation.Receipt, bool, error) {
	if p == nil || ctx == nil || step.Validate() != nil {
		return compensation.Receipt{}, false, compensation.ErrInvalid
	}
	// This private Engine lease is control authority, not an expired/revoked
	// business execution approval and not an HTTP-supplied permission marker.
	if _, err := compensation.LeaseFromContext(ctx, step); err != nil {
		return compensation.Receipt{}, false, err
	}
	tx, err := p.tools.db.BeginTx(ctx, nil)
	if err != nil {
		return compensation.Receipt{}, false, compensation.ErrUnavailable
	}
	defer tx.Rollback()
	if err = p.ledger.GuardRegisteredStopTx(ctx, tx, step); err != nil {
		return compensation.Receipt{}, false, err
	}
	fact, err := p.tools.ReadCancellationToolTx(ctx, tx, step.Scope, step.CallID)
	if err != nil || fact.Phase != "executing" {
		return compensation.Receipt{}, false, compensation.ErrConflict
	}
	q := fact.Query
	descriptor, registered := p.provider.DescribeTool(q.Name)
	if !registered || q.RuntimeAudit == nil || descriptor != q.RuntimeAudit.Descriptor {
		return compensation.Receipt{}, false, compensation.ErrConflict
	}
	expected, err := p.provider.cancellationStep(q, p.version)
	if err != nil || expected.Digest() != step.Digest() {
		return compensation.Receipt{}, false, compensation.ErrConflict
	}
	b, found := p.provider.scopedTool(q.Scope, q.Name)
	if !found {
		return compensation.Receipt{}, false, compensation.ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return compensation.Receipt{}, false, compensation.ErrUnavailable
	}
	now := time.Now()
	expires := now.Add(9 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	scope := q.Scope
	permit := protocol.Permit{Version: "code-permit/v1", Action: "receipt", ControllerID: b.binding.ControllerID, ScopeHash: ToolReceiptScopeHash(scope), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, CallerID: scope.PrincipalID, CallerType: scope.PrincipalType, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, AgentInstanceID: scope.AgentInstanceID, InstallationID: scope.InstallationID, RunID: scope.RunID, SessionID: scope.SessionID, TraceID: scope.TraceID, AuthorizationEpoch: scope.AuthorizationEpoch, PolicyHash: q.RuntimeAudit.PolicyHash, ApprovalID: "cancel-control-" + step.CompensationKey(), ToolName: q.Name, CallID: q.CallID, Fingerprint: q.Fingerprint, ProfileID: b.binding.ProfileID, Language: b.binding.Language, Limits: b.binding.Limits, IssuedAt: now.Unix(), ExpiresAt: expires.Unix()}
	if permit.Validate(now) != nil {
		return compensation.Receipt{}, false, compensation.ErrInvalid
	}
	var evidence string
	_, confirmed, err := p.provider.requestWithProof(ctx, b, permit, func(r *protocol.Result) {
		// The controller has validated append-only operation identity and closed
		// future replay; the adapter has checked limits, outcome and removal.
		// Never retain stdout, stderr, source code or raw provider error.
		raw, _ := json.Marshal(struct {
			Step, Operation, Controller, Profile, Status, Error string
			Started, Finished                                   time.Time
			Removed                                             bool
			Limits                                              protocol.Limits
		}{step.Digest(), protocol.OperationKey(permit), permit.ControllerID, permit.ProfileID, r.Status, r.ErrorType, r.StartedAt, r.FinishedAt, r.ContainerRemoved, r.Limits})
		h := sha256.Sum256(raw)
		evidence = hex.EncodeToString(h[:])
	})
	if err != nil {
		return compensation.Receipt{}, false, compensation.ErrUnavailable
	}
	if !confirmed || evidence == "" {
		return compensation.Receipt{}, false, nil
	}
	r := compensation.Receipt{Version: compensation.ContractVersion, StepDigest: step.Digest(), Key: step.CompensationKey(), Action: "no_effect", EvidenceDigest: evidence}
	return r, true, r.Validate(step)
}

func (p *codeCancellationPort) Lookup(ctx context.Context, s compensation.Step) (compensation.Receipt, bool, error) {
	return p.cleanup(ctx, s)
}
func (p *codeCancellationPort) InspectOriginal(ctx context.Context, s compensation.Step) (compensation.OriginalEffect, error) {
	r, found, err := p.cleanup(ctx, s)
	if err != nil {
		return compensation.OriginalEffect{}, err
	}
	if !found {
		return compensation.OriginalEffect{StepDigest: s.Digest(), State: "unknown"}, nil
	}
	return compensation.OriginalEffect{StepDigest: s.Digest(), State: "no_effect", EvidenceDigest: r.EvidenceDigest}, nil
}
func (*codeCancellationPort) Compensate(context.Context, compensation.Step) (compensation.Receipt, error) {
	// Code must never be replayed as a compensation. Cleanup is controller
	// owned and is proved only by reading its durable completion receipt.
	return compensation.Receipt{}, errors.Join(compensation.ErrNotSubmitted, compensation.ErrPending)
}
