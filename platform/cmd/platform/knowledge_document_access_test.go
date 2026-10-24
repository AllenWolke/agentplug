package main

import (
	"context"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestKnowledgeDocumentsIntersectCallerAndMachineDataScope(t *testing.T) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "role", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}
	grant := identity.Grant{ID: "caller", SubjectID: "u", SubjectType: identity.PrincipalUser, TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller.Grants = []identity.Grant{grant}
	machineGrant := grant
	machineGrant.ID = "machine"
	machineGrant.SubjectID = "executor"
	machineGrant.SubjectType = identity.PrincipalServicePrincipal
	machineGrant.DataScope = identity.DataScope{Type: "approved_organization"}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{machineGrant}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i", AgentID: "agent", AgentVersionID: "v"}
	documents := []policyasset.KnowledgeDocumentBinding{{KnowledgeScope: "kb", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "42", OwnerID: "u", OwnershipSource: "reviewed:42", DocumentVersion: "v1", Status: "active"}, {KnowledgeScope: "kb", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "43", OwnerID: "other", OwnershipSource: "reviewed:43", DocumentVersion: "v1", Status: "active"}}
	snapshotReads, bindingReads, credentialReads := 0, 0, 0
	check := func() (capability.KnowledgeDocumentPlan, error) {
		return (capabilityExecutionAuthority{identity: capabilitySnapshotFixture{snapshot: caller, executor: &executor, binding: &binding,
			snapshotReads: &snapshotReads, bindingReads: &bindingReads, credentialReads: &credentialReads}}).FilterKnowledgeDocuments(context.Background(), scope, "kb", documents)
	}
	plan, err := check()
	if err != nil || plan.Legacy || len(plan.Documents) != 1 || plan.Documents[0].ProviderDocumentID != "42" {
		t.Fatal("owner range ignored", plan, err)
	}
	if snapshotReads != 2 || bindingReads != 1 || credentialReads != 1 {
		t.Fatal("one document pass must use both independently authorized snapshots without redundant reloads", snapshotReads, bindingReads, credentialReads)
	}
	caller.Grants[0].DataScope = identity.DataScope{Type: "approved_organization"}
	deny := grant
	deny.ID = "deny-42"
	deny.Effect = "deny"
	deny.DataScope = identity.DataScope{Type: "explicit_set", IDs: []string{documents[0].ObjectID()}}
	caller.Grants = append(caller.Grants, deny)
	plan, err = check()
	if err != nil || len(plan.Documents) != 1 || plan.Documents[0].ProviderDocumentID != "43" {
		t.Fatal("document deny became scope-wide or was ignored", plan, err)
	}
	if snapshotReads != 4 || bindingReads != 2 || credentialReads != 2 {
		t.Fatal("later pass reused prior authority instead of checking live state", snapshotReads, bindingReads, credentialReads)
	}
	executor.Grants[0].DataScope = identity.DataScope{Type: "explicit_set", IDs: []string{documents[0].ObjectID()}}
	plan, err = check()
	if err != nil || len(plan.Documents) != 0 {
		t.Fatal("executor authority expanded caller range", plan, err)
	}
	executor.Grants[0].DataScope = identity.DataScope{Type: "approved_organization"}
	until := time.Now().Add(-time.Second)
	documents[1].ValidUntil = &until
	plan, err = check()
	if err != nil || len(plan.Documents) != 0 {
		t.Fatal("document expiry ignored", plan, err)
	}
	documents[1].ValidUntil = nil
	documents[1].Status = "deleted"
	plan, err = check()
	if err != nil || len(plan.Documents) != 0 {
		t.Fatal("deleted binding admitted", plan, err)
	}
	documents[1].Status = "active"
	scope.ApplicationID = "foreign"
	if _, err := check(); err == nil {
		t.Fatal("document facts crossed application")
	}
	scope.ApplicationID = "a"
	binding.Status = "revoked"
	if _, err := check(); err == nil {
		t.Fatal("revoked execution identity admitted")
	}
	caller.Mode = "legacy"
	plan, err = check()
	if err != nil || !plan.Legacy {
		t.Fatal("explicit legacy compatibility changed", err)
	}
}
