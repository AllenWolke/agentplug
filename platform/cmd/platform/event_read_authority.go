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
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, "history.read")
	if err != nil || epoch != scope.AuthorizationEpoch {
		return errors.New("current event IAM denied")
	}
	target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
	if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
		return errors.New("event installation denied")
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
