package modelgovernance

import (
	"context"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// AccessResolver adapts model catalog approval and scoped access-policy
// evaluation to the Model Gateway's invocation-time resolver port.
type AccessResolver struct {
	Store    Store
	Capacity interface {
		ResolveReadyDeployment(context.Context, sharedkernel.Scope, string) (modelcapacity.RuntimeDeployment, error)
	}
}

func (r AccessResolver) ResolveModel(ctx context.Context, scope sharedkernel.Scope, modelVersionID string) (modelgateway.Selection, error) {
	if r.Store == nil || scope.ValidateTrusted() != nil {
		return modelgateway.Selection{}, ErrInvalidRequest
	}
	resolved, err := r.Store.GetResolvedVersion(ctx, modelVersionID)
	if err != nil {
		return modelgateway.Selection{}, err
	}
	if resolved.VersionStatus != StatusApproved || resolved.ProviderStatus != StatusApproved || resolved.ProviderID == "" || resolved.DefinitionID == "" {
		return modelgateway.Selection{}, ErrModelAccessDenied
	}
	accessScope := ModelAccessScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: scope.InstallationID, AgentVersionID: scope.AgentVersionID, PrincipalID: scope.PrincipalID}
	policies, err := r.Store.ListApplicableAccessPolicies(ctx, accessScope)
	if err != nil {
		return modelgateway.Selection{}, err
	}
	if err = evaluateAccessPolicies(policies, accessScope, resolved.ProviderID, resolved.DefinitionID, resolved.TrustZone, nowUTC()); err != nil {
		return modelgateway.Selection{}, err
	}
	selection := modelgateway.Selection{ModelVersionID: resolved.VersionID, ProviderID: resolved.ProviderID, ProviderKey: resolved.ProviderKey, ModelID: resolved.DefinitionID, ModelKey: resolved.ModelKey, TrustZone: resolved.TrustZone}
	if resolved.TrustZone == TrustLocal {
		if r.Capacity == nil {
			return modelgateway.Selection{}, modelcapacity.ErrUnavailable
		}
		deployment, deploymentErr := r.Capacity.ResolveReadyDeployment(ctx, scope, modelVersionID)
		if deploymentErr != nil || deployment.ID == "" || deployment.ModelVersionID != modelVersionID || deployment.EndpointRef == "" || deployment.CapacityUnits <= 0 {
			if deploymentErr != nil {
				return modelgateway.Selection{}, deploymentErr
			}
			return modelgateway.Selection{}, modelcapacity.ErrUnavailable
		}
		selection.DeploymentID = deployment.ID
		selection.EndpointRef = deployment.EndpointRef
		selection.CapacityUnits = deployment.CapacityUnits
	}
	return selection, nil
}

func nowUTC() time.Time { return time.Now().UTC() }

var _ modelgateway.AccessResolver = AccessResolver{}
