package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestAuditContentUsesTrustedRunAndIndependentResourceDataGrant(t *testing.T) {
	ctx := context.Background()
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "auditor", TenantID: "t", IsActive: true, Roles: []string{"admin", "auditor"}}
	actor := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "auditor"}
	owner := actor
	owner.PrincipalID = "business-owner"
	owner.RunID = "run"
	owner.AgentInstanceID = "installation"
	event := audit.Event{ID: "event", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AggregateType: "agent_run", AggregateID: "run", ActorID: "untrusted-event-actor"}
	grant := identity.Grant{ID: "content", SubjectType: identity.PrincipalUser, SubjectID: p.ID, TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceType: "agent_installation", ResourceID: "installation", AgentInstanceID: "installation", Action: "audit.content.read", Effect: "allow", Status: "active", DataScope: identity.DataScope{Type: "explicit_set", IDs: []string{"run"}}}
	for _, scenario := range []string{"allowed", "no-grant", "no-role", "owner-not-auditor", "wrong-installation", "deny", "expired", "export-separate", "inactive", "foreign-owner", "wrong-run", "event-actor-not-owner", "legacy", "policy-outage"} {
		t.Run(scenario, func(t *testing.T) {
			s := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "membership", SubjectID: p.ID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "auditor", SubjectID: p.ID, RoleCode: "auditor", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{grant}}}
			run := owner
			action := "audit.content.read"
			switch scenario {
			case "no-grant":
				s.snapshot.Grants = nil
			case "no-role":
				s.snapshot.Bindings = nil
			case "owner-not-auditor":
				s.snapshot.Grants[0].DataScope = identity.DataScope{Type: "owner"}
			case "wrong-installation":
				s.snapshot.Grants[0].ResourceID = "another"
			case "deny":
				deny := grant
				deny.ID = "deny"
				deny.Effect = "deny"
				s.snapshot.Grants = append(s.snapshot.Grants, deny)
			case "expired":
				expired := time.Now().Add(-time.Second)
				s.snapshot.Grants[0].Validity.ExpiresAt = &expired
			case "export-separate":
				action = "audit.export"
			case "inactive":
				s.snapshot.Principal.IsActive = false
			case "foreign-owner":
				run.TenantID = "foreign"
			case "wrong-run":
				run.RunID = "other"
			case "event-actor-not-owner":
				s.snapshot.Grants[0].DataScope = identity.DataScope{Type: "owner"}
			case "legacy":
				s.snapshot.Mode = "legacy"
			case "policy-outage":
				s.policyError = errors.New("identity unavailable")
			}
			calls := 0
			a := &identityAuditContentControl{store: s, runs: assignmentRunStub{scope: run, calls: &calls}}
			err := a.Authorize(ctx, actor, event, action)
			if (err == nil) != (scenario == "allowed") {
				t.Fatal(scenario, err)
			}
			if scenario == "policy-outage" && !errors.Is(err, s.policyError) {
				t.Fatal("policy outage hidden", err)
			}
		})
	}
}
