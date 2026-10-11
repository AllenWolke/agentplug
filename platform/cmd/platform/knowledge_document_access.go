package main

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// A document-specific deny is checked against its real document below. It
// must not deny every document merely because the resource gate has no Object.
func capabilityResourceEligibility(snapshot identity.PermissionSnapshot, access capability.CapabilityResourceAccess) identity.PermissionSnapshot {
	if access.ResourceType != "knowledge" || access.Action != "knowledge.search" {
		return snapshot
	}
	filtered := make([]identity.Grant, 0, len(snapshot.Grants))
	for _, g := range snapshot.Grants {
		if g.Action == access.Action && g.ResourceType == access.ResourceType && g.ResourceID == access.ResourceID && g.Effect == "deny" && g.DataScope.Validate() == nil && g.DataScope.Type != "approved_organization" {
			continue
		}
		filtered = append(filtered, g)
	}
	snapshot.Grants = filtered
	return snapshot
}

func (a capabilityExecutionAuthority) FilterKnowledgeDocuments(ctx context.Context, scope sharedkernel.Scope, knowledgeScope string, documents []policyasset.KnowledgeDocumentBinding) (capability.KnowledgeDocumentPlan, error) {
	plan := capability.KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{}}
	source, ok := a.identity.(interface {
		PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error)
	})
	if !ok {
		return plan, errors.New("knowledge IAM unavailable")
	}
	caller, err := source.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil {
		return plan, err
	}
	if caller.Mode == "legacy" || caller.Mode == "shadow" {
		plan.Legacy = true
		return plan, nil
	}
	if caller.Mode != "v2" {
		return plan, identity.ErrPermissionDenied
	}
	access := capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: knowledgeScope}
	if err := a.AuthorizeCapabilityResource(ctx, scope, access); err != nil {
		return plan, err
	}
	resolver, ok := a.identity.(identity.WorkloadIdentityResolver)
	if !ok {
		return plan, identity.ErrPermissionDenied
	}
	binding, err := resolver.ResolveWorkloadIdentity(ctx, scope)
	if err != nil {
		return plan, err
	}
	executor, err := source.PermissionSnapshot(ctx, identity.PrincipalServicePrincipal, binding.PrincipalID)
	if err != nil {
		return plan, err
	}
	caller.Assignments, executor.Assignments = nil, nil
	now := time.Now().UTC()
	installation := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}
	for _, document := range documents {
		if document.KnowledgeScope != knowledgeScope || !document.Effective(now) {
			continue
		}
		object := identity.DataObject{ID: document.ObjectID(), OwnerID: document.OwnerID, Scope: installation}
		query := identity.PermissionQuery{Action: access.Action, Scope: installation, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Object: &object, Now: now}
		userDecision, err := identity.EvaluatePermission(caller, query)
		if err != nil {
			return plan, err
		}
		machineDecision, err := identity.EvaluatePermission(executor, query)
		if err != nil {
			return plan, err
		}
		if userDecision.Allowed && machineDecision.Allowed {
			plan.Documents = append(plan.Documents, document)
		}
	}
	return plan, nil
}
