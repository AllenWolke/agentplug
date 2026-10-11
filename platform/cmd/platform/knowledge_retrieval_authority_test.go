package main

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type selectedSourceFixture func(context.Context, knowledge.ProjectionScope, []string) (knowledge.SourceSnapshot, error)

func (f selectedSourceFixture) SnapshotDocuments(ctx context.Context, s knowledge.ProjectionScope, ids []string) (knowledge.SourceSnapshot, error) {
	return f(ctx, s, ids)
}

func TestCurrentKnowledgeSourceIntersectsCallerMachineAndPublication(t *testing.T) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	grant := identity.Grant{ID: "caller", SubjectID: "u", SubjectType: identity.PrincipalUser, TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "role", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}
	grant.ID, grant.SubjectID, grant.SubjectType, grant.DataScope = "machine", "executor", identity.PrincipalServicePrincipal, identity.DataScope{Type: "approved_organization"}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{grant}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
	publication := policyasset.KnowledgeDocumentBinding{KnowledgeScope: "kb", ProviderID: "platform-knowledge", KnowledgeBaseID: "kb", ProviderDocumentID: "doc", OwnerID: "u", OwnershipSource: "source:kb/doc", DocumentVersion: "1", Status: "active"}
	base := knowledge.SourceDocument{ID: "doc", Version: 1, SourceRevision: 1, ACLRevision: 1, Body: "internal body", ACL: knowledge.DocumentACL{OwnerPrincipalID: "u", Readers: []string{"executor"}}}
	for _, mode := range []string{"allowed", "deleted", "source-version", "source-owner", "caller-acl", "machine-acl", "iam-revoked-during-read", "foreign-workspace", "stale-epoch", "unexpected-source-document"} {
		t.Run(mode, func(t *testing.T) {
			human := caller
			human.Grants = append([]identity.Grant(nil), caller.Grants...)
			declared := publication
			machine := executor
			machine.Grants = append([]identity.Grant(nil), executor.Grants...)
			document := base
			if mode == "deleted" {
				document.Deleted = true
				document.Body = ""
			}
			if mode == "source-version" {
				document.Version = 2
			}
			if mode == "source-owner" {
				document.ACL.OwnerPrincipalID = "other"
			}
			if mode == "machine-acl" {
				document.ACL.Readers = nil
			}
			if mode == "caller-acl" {
				human.Grants[0].DataScope = identity.DataScope{Type: "approved_organization"}
				declared.OwnerID = "other"
				document.ACL.OwnerPrincipalID = "other"
				document.ACL.Readers = []string{"executor"}
			}
			if mode == "unexpected-source-document" {
				document.ID = "unknown"
			}
			reads := 0
			port := selectedSourceFixture(func(_ context.Context, s knowledge.ProjectionScope, ids []string) (knowledge.SourceSnapshot, error) {
				reads++
				if s.ApplicationID != "a" || len(ids) != 1 || ids[0] != "doc" {
					t.Fatal("untrusted source selection")
				}
				if mode == "iam-revoked-during-read" {
					machine.Grants[0].Status = "disabled"
				}
				return knowledge.SourceSnapshot{Revision: 1, Documents: []knowledge.SourceDocument{document}}, nil
			})
			a := sourceKnowledgeAuthority{source: port, iam: capabilityExecutionAuthority{identity: capabilitySnapshotFixture{snapshot: human, executor: &machine, binding: &binding}}, scope: scope, knowledgeID: "kb", documents: []policyasset.KnowledgeDocumentBinding{declared}}
			requestScope := scope
			if mode == "foreign-workspace" {
				requestScope.ApplicationID = "foreign"
			}
			if mode == "stale-epoch" {
				requestScope.AuthorizationEpoch = 2
				a.scope = requestScope
			}
			facts, err := a.ResolveCurrentDocuments(context.Background(), requestScope, "kb")
			if mode == "allowed" {
				if err != nil || len(facts) != 1 || facts[0].Version != "1" || facts[0].ACLRevision != "1" {
					t.Fatal("current facts missing", err)
				}
			} else if len(facts) != 0 {
				t.Fatal("denied source admitted", facts)
			}
			if (mode == "foreign-workspace" || mode == "stale-epoch") && (err == nil || reads != 0) {
				t.Fatal("invalid caller reached source")
			}
			if mode == "unexpected-source-document" && err == nil {
				t.Fatal("unexpected source identity accepted")
			}
		})
	}
}
