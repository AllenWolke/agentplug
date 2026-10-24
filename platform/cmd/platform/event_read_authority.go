package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (a capabilityExecutionAuthority) AuthorizeEventRead(ctx context.Context, scope sharedkernel.Scope, policyHash string) error {
	reader, ok := a.execution.(interface {
		ValidateEventRead(context.Context, sharedkernel.Scope, string) error
	})
	if !ok || a.identity == nil || a.catalog == nil {
		return errors.New("event authority unavailable")
	}
	if err := reader.ValidateEventRead(ctx, scope, policyHash); err != nil {
		return err
	}
	origin := scope
	if resolver, ok := a.execution.(interface {
		EventReadOriginScope(context.Context, sharedkernel.Scope, string) (sharedkernel.Scope, error)
	}); ok {
		var err error
		origin, err = resolver.EventReadOriginScope(ctx, scope, policyHash)
		if err != nil || origin.ValidateTrusted() != nil {
			return errors.New("event execution origin denied")
		}
		stored, requested := origin, scope
		stored.AuthorizationEpoch, stored.TraceID = 0, ""
		requested.AuthorizationEpoch, requested.TraceID = 0, ""
		if stored != requested {
			return errors.New("event execution attribution denied")
		}
	}
	// IAM epochs are keyed by action. A renewed run proof cannot be compared
	// with history.read's independently advanced epoch. Verify current execution
	// authority first, then the separate fresh history grant. Legacy adapters
	// without the owner receipt port retain their original exact-epoch boundary.
	_, hasProofOwner := a.execution.(interface {
		ExpectedAuthorizationEpoch(context.Context, sharedkernel.Scope) (uint64, error)
	})
	if hasProofOwner {
		if err := a.AuthorizeCurrentRunEpoch(ctx, origin); err != nil {
			return errors.Join(errors.New("current event execution authority denied"), err)
		}
	}
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, "history.read")
	if err != nil {
		return errors.Join(errors.New("current event IAM denied"), err)
	}
	if epoch == 0 || !hasProofOwner && epoch != scope.AuthorizationEpoch {
		return errors.New("current event IAM denied")
	}
	if pinned, ok := a.execution.(interface {
		ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error
	}); ok {
		if err := pinned.ValidatePinnedRunTarget(ctx, origin); err != nil {
			return errors.Join(errors.New("event installation denied"), err)
		}
	} else {
		target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, origin, origin.AgentID, origin.AgentVersionID)
		if err != nil {
			return errors.Join(errors.New("event installation denied"), err)
		}
		if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
			return errors.New("event installation denied")
		}
	}
	// Both caller and bound machine need explicit read authority; no implicit
	// history permission is derived from model or execution rights.
	if err := a.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{
		Action: "history.read", ResourceType: "agent_installation", ResourceID: scope.InstallationID,
	}); err != nil {
		return err
	}
	// Recheck ownership/policy after current IAM and machine authorization.
	return reader.ValidateEventRead(ctx, scope, policyHash)
}
