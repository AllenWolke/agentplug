package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Installed by the local composition root, never a browser-supplied handler.
// A write binding pins both its runtime descriptor and inverse effect spec.
type cancellationToolBinding struct {
	descriptor capability.RuntimeToolDescriptor
	step       func(capability.ToolReceiptQuery) (compensation.Step, error)
}

type cancellationEffects struct {
	routes       *agentcoordination.SQLRouteStore
	tools        *capability.SQLToolInvocationStore
	capabilities *capability.Module
	ledger       compensation.Coordinator
	bindings     map[string]cancellationToolBinding
}

func cancellationDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func (c *cancellationEffects) toolStep(q capability.ToolReceiptQuery) (compensation.Step, bool, error) {
	if c == nil || c.capabilities == nil || q.Scope.ValidateTrusted() != nil || q.CallID == "" || !cancellationDigest(q.Fingerprint) || q.RuntimeAudit == nil || !cancellationDigest(q.RuntimeAudit.PolicyHash) || q.RuntimeAudit.Descriptor.Validate() != nil {
		return compensation.Step{}, false, compensation.ErrConflict
	}
	current, found := c.capabilities.RuntimeToolDescriptor(q.Name)
	if !found || current != q.RuntimeAudit.Descriptor {
		return compensation.Step{}, false, compensation.ErrConflict
	}
	if current.Risk == "read_only" {
		return compensation.Step{}, false, nil
	}
	binding, found := c.bindings[q.Name]
	if !found || binding.step == nil || binding.descriptor != current {
		return compensation.Step{}, false, compensation.ErrUnavailable
	}
	step, err := binding.step(q)
	if err != nil {
		return compensation.Step{}, false, err
	}
	if step.Validate() != nil || step.Root != q.Scope || step.Scope != q.Scope || step.Tool != q.Name || step.CallID != q.CallID || step.Fingerprint != q.Fingerprint {
		return compensation.Step{}, false, compensation.ErrConflict
	}
	return step, true, nil
}

func (c *cancellationEffects) validateStep(_ context.Context, _ *sql.Tx, step compensation.Step) error {
	if c == nil || step.Validate() != nil || step.Root != step.Scope {
		return compensation.ErrConflict
	}
	switch step.Kind {
	case "memory":
		if step.Provider == "platform.memory" && step.ProviderVersion == "memory-undo.v1" && step.Tool == "memory.save" && cancellationDigest(step.Ref) {
			return nil
		}
	case "index":
		if step.Provider == knowledge.IndexCompensationProvider && step.ProviderVersion == knowledge.IndexCompensationVersion && step.Tool == "knowledge.index.publish" && cancellationDigest(step.Ref) {
			return nil
		}
	case "tool", "api", "notification":
		binding, found := c.bindings[step.Tool]
		if !found || binding.step == nil {
			return compensation.ErrUnavailable
		}
		q := capability.ToolReceiptQuery{Scope: step.Scope, Name: step.Tool, CallID: step.CallID, Fingerprint: step.Fingerprint}
		expected, err := binding.step(q)
		if err != nil {
			return err
		}
		if expected.Validate() == nil && expected.Digest() == step.Digest() {
			return nil
		}
	}
	return compensation.ErrConflict
}

// Checks immutable metadata only. UNKNOWN remains in the original ledger. A
// stopped write may enter compensation only with its exact preregistration;
// actual no-effect/inverse evidence is subsequently required by the engine.
func (c *cancellationEffects) validateToolCoverage(scope sharedkernel.Scope, facts []capability.CancellationToolFact, effects []compensation.Step) error {
	set := make(map[string]compensation.Step, len(effects))
	for _, step := range effects {
		if step.Scope != scope || c.validateStep(context.Background(), nil, step) != nil {
			return compensation.ErrConflict
		}
		if _, duplicate := set[step.ID]; duplicate {
			return compensation.ErrConflict
		}
		set[step.ID] = step
	}
	seen := make(map[string]bool, len(facts))
	for _, fact := range facts {
		q := fact.Query
		if q.Scope != scope || seen[q.CallID] || (fact.Status != "running" && fact.Status != "unknown" && fact.Status != "completed" && fact.Status != "failed") || (fact.Phase != "preparing" && fact.Phase != "executing") {
			return compensation.ErrConflict
		}
		seen[q.CallID] = true
		step, write, err := c.toolStep(q)
		if err != nil {
			return err
		}
		if !write {
			continue
		}
		actual, registered := set[step.ID]
		if fact.Phase == "preparing" {
			// BeginTool atomically commits registration with phase=executing.
			// A stopped preparation cannot have submitted the forward operation.
			if registered || fact.Status == "completed" {
				return compensation.ErrConflict
			}
			continue
		}
		if !registered || actual.Digest() != step.Digest() {
			return compensation.ErrPending
		}
		delete(set, step.ID)
	}
	// Memory and index owners register without a tool invocation. Any other
	// orphan effect, including an extra notification, blocks finalization.
	for _, step := range set {
		if step.Kind != "memory" && step.Kind != "index" {
			return compensation.ErrConflict
		}
	}
	return nil
}

func (c *cancellationEffects) checkScope(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if c == nil || c.tools == nil || c.ledger == nil || c.capabilities == nil || tx == nil {
		return compensation.ErrUnavailable
	}
	if err := c.capabilities.CheckTaskModelQuiescence(ctx, scope); err != nil {
		return err
	}
	facts, err := c.tools.ReadCancellationToolsTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	effects, err := c.ledger.RecordedEffectsTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	return c.validateToolCoverage(scope, facts, effects)
}

func (c *cancellationEffects) stoppedScopes(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) ([]sharedkernel.Scope, error) {
	if c == nil || c.routes == nil {
		return nil, compensation.ErrUnavailable
	}
	if err := c.checkScope(ctx, tx, scope); err != nil {
		return nil, err
	}
	return c.routes.ReadCancellationTreeScopesTx(ctx, tx, scope, c.checkScope)
}

type cancellationTreeProofKey struct{}
type cancellationTreeProof struct {
	tx      *sql.Tx
	control sharedkernel.Scope
	scopes  []sharedkernel.Scope
}

func (c *cancellationEffects) ports(guard func(context.Context, *sql.Tx, compensation.Step) error) execution.CancellationCompensationPorts {
	return execution.CancellationCompensationPorts{
		GuardForwardTx: guard, ValidateStepTx: c.validateStep,
		PrepareCoverageTx: func(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, ledger compensation.Coordinator) error {
			if c.ledger == nil || ledger != c.ledger {
				return compensation.ErrUnavailable
			}
			scopes, err := c.stoppedScopes(ctx, tx, control)
			if err != nil {
				return err
			}
			// Reuse only this transaction's authoritative tree while enrolling.
			// Revalidating the entire tree once per effect is quadratic.
			ctx = context.WithValue(ctx, cancellationTreeProofKey{}, cancellationTreeProof{tx, control, scopes})
			return ledger.EnrollStoppedTreeTx(ctx, tx, control, scopes)
		},
		ValidateCoverageTx: func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
			scopes, err := c.stoppedScopes(ctx, tx, scope)
			if err != nil {
				return err
			}
			return c.ledger.VerifyStoppedTreeCoverageTx(ctx, tx, scope, scopes)
		},
		ValidateEnrollmentTx: func(ctx context.Context, tx *sql.Tx, control sharedkernel.Scope, step compensation.Step) error {
			if step.Root != step.Scope || c.validateStep(ctx, tx, step) != nil {
				return compensation.ErrConflict
			}
			proof, joined := ctx.Value(cancellationTreeProofKey{}).(cancellationTreeProof)
			var scopes []sharedkernel.Scope
			if joined && proof.tx == tx && proof.control == control {
				scopes = proof.scopes
			} else {
				var err error
				scopes, err = c.stoppedScopes(ctx, tx, control)
				if err != nil {
					return err
				}
			}
			for _, scope := range scopes {
				if scope == step.Scope {
					return nil
				}
			}
			return errors.Join(compensation.ErrConflict, compensation.ErrPending)
		},
	}
}
