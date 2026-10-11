package main

import (
	"context"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type machineIdentityAdapter struct{ module *identity.Module }

func (a machineIdentityAdapter) AuthorizeMachineRun(ctx context.Context, rawToken, remoteAddr, action string, scope sharedkernel.Scope, runID string) error {
	return a.module.AuthorizeMachineRunToken(ctx, rawToken, remoteAddr, action, scope, runID)
}

func (a machineIdentityAdapter) AuthenticateMachine(ctx context.Context, rawToken, remoteAddr, action string) (execution.MachineAccess, error) {
	verified, err := a.module.AuthenticateMachineToken(ctx, rawToken, remoteAddr, action)
	if err != nil {
		return execution.MachineAccess{}, err
	}
	return execution.MachineAccess{Scope: verified.Scope, AuthorizationEpoch: verified.AuthorizationEpoch}, nil
}

type machineCatalogAdapter struct{ module *catalog.Module }

func (a machineCatalogAdapter) ResolveMachineTarget(ctx context.Context, scope sharedkernel.Scope) (execution.MachineAgentTarget, error) {
	target, err := a.module.ResolveMachineAgentTarget(ctx, scope)
	if err != nil {
		return execution.MachineAgentTarget{}, err
	}
	return execution.MachineAgentTarget{AgentID: target.AgentID, InstallationID: target.InstallationID, VersionID: target.VersionID,
		InputSchemaURI: target.InputSchemaURI, Endpoint: target.Endpoint, Revision: target.Revision}, nil
}
