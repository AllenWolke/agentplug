package main

import (
	"context"
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
	access := capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: knowledgeScope}
	snapshots, err := a.authorizedResourceSnapshots(ctx, scope, access)
	if err != nil {
		return plan, err
	}
	return knowledgeDocumentsFromSnapshots(snapshots, scope, knowledgeScope, documents, time.Now().UTC())
}

// Pure projection of already fenced facts. The owner must keep the IAM read
// fence until its local read ends; each projection evaluates time afresh.
func knowledgeDocumentsFromSnapshots(snapshots authorizedResourceSnapshots, scope sharedkernel.Scope, knowledgeScope string, documents []policyasset.KnowledgeDocumentBinding, now time.Time) (capability.KnowledgeDocumentPlan, error) {
	plan := capability.KnowledgeDocumentPlan{Documents: []policyasset.KnowledgeDocumentBinding{}}
	access := capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: knowledgeScope}
	caller, executor := snapshots.caller, snapshots.executor
	if caller.Mode == "legacy" || caller.Mode == "shadow" {
		plan.Legacy = true
		return plan, nil
	}
	caller.Assignments, executor.Assignments = nil, nil
	installation := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}
	queries := []identity.PermissionQuery{}
	documentsToCheck := []policyasset.KnowledgeDocumentBinding{}
	for _, document := range documents {
		if document.KnowledgeScope != knowledgeScope || !document.Effective(now) {
			continue
		}
		object := identity.DataObject{ID: document.ObjectID(), OwnerID: document.OwnerID, Scope: installation}
		query := identity.PermissionQuery{Action: access.Action, Scope: installation, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Object: &object, Now: now}
		queries = append(queries, query)
		documentsToCheck = append(documentsToCheck, document)
	}
	users, err := identity.EvaluatePermissions(caller, queries)
	if err != nil {
		return plan, err
	}
	machines, err := identity.EvaluatePermissions(executor, queries)
	if err != nil {
		return plan, err
	}
	for index, document := range documentsToCheck {
		if users[index].Allowed && machines[index].Allowed {
			plan.Documents = append(plan.Documents, document)
		}
	}
	return plan, nil
}
