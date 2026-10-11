package identity

import (
	"slices"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestManagedLegacyCancellationRecoveryRespectsOriginalAuthority(t *testing.T) {
	now := time.Now().UTC()
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	for _, test := range []struct {
		name    string
		mutate  func(*PermissionSnapshot)
		allowed bool
		invalid bool
	}{
		{name: "effective original grant", allowed: true},
		{name: "shadow recovery", mutate: func(s *PermissionSnapshot) { s.Mode = "shadow" }, allowed: true},
		{name: "expired", mutate: func(s *PermissionSnapshot) { s.Grants[1].ExpiresAt = &past }},
		{name: "not started", mutate: func(s *PermissionSnapshot) { s.Grants[1].StartsAt = &future }},
		{name: "expiry boundary", mutate: func(s *PermissionSnapshot) { s.Grants[1].ExpiresAt = &now }},
		{name: "start boundary", mutate: func(s *PermissionSnapshot) { s.Grants[1].StartsAt = &now }, allowed: true},
		{name: "explicit denial", mutate: func(s *PermissionSnapshot) {
			deny := s.Grants[1]
			deny.ID, deny.Effect = "cancel-denied", "deny"
			s.Grants = append(s.Grants, deny)
		}},
		{name: "expired denial", mutate: func(s *PermissionSnapshot) {
			deny := s.Grants[1]
			deny.ID, deny.Effect, deny.ExpiresAt = "old-cancel-denied", "deny", &past
			s.Grants = append(s.Grants, deny)
		}, allowed: true},
		{name: "revoked", mutate: func(s *PermissionSnapshot) { s.Grants[1].Status = GrantRevoked }},
		{name: "no original grant", mutate: func(s *PermissionSnapshot) { s.Grants = s.Grants[:1] }},
		{name: "wrong resource", mutate: func(s *PermissionSnapshot) { s.Grants[1].ResourceID = "another-agent" }, invalid: true},
		{name: "malformed validity", mutate: func(s *PermissionSnapshot) {
			s.Grants[1].StartsAt, s.Grants[1].ExpiresAt = &future, &past
		}, invalid: true},
		{name: "inactive principal", mutate: func(s *PermissionSnapshot) { s.Principal.IsActive = false }, invalid: true},
		{name: "v2 excluded", mutate: func(s *PermissionSnapshot) { s.Mode = "v2" }, invalid: true},
		{name: "unmanaged excluded", mutate: func(s *PermissionSnapshot) { s.DepartmentAgentPolicies = nil }, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, query := departmentAgentPermissionFixture(now)
			snapshot.Mode = "legacy"
			// Removing the department ceiling preserves only effective original
			// cancellation authority, without granting any new recovery rights.
			snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{nextDepartmentAgentPolicy(DepartmentAgentPolicy{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID}, nil)}
			if test.mutate != nil {
				test.mutate(&snapshot)
			}
			scope := sharedkernel.Scope{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID, AgentInstanceID: query.ResourceID, PrincipalID: snapshot.Principal.ID, PrincipalType: string(snapshot.Principal.Type)}
			decision, err := evaluateManagedLegacyCancellation(snapshot, scope, now)
			if (err != nil) != test.invalid || decision.Allowed != test.allowed {
				t.Fatalf("allowed=%v reason=%s error=%v", decision.Allowed, decision.Reason, err)
			}
		})
	}
}

func TestDepartmentAgentActionRestorePreservesIndependentSourcesAndDenials(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	policy := nextDepartmentAgentPolicy(DepartmentAgentPolicy{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID}, []DepartmentAgentPolicyEntry{{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run", "history.read", "cancel"}}})
	for i := range snapshot.Grants {
		snapshot.Grants[i].DepartmentAgentActionVersion = policy.Entries[0].ActionVersions[snapshot.Grants[i].Action]
	}
	check := func(action string, allowed bool) {
		t.Helper()
		query.Action = action
		snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{policy}
		decision, err := EvaluatePermission(snapshot, query)
		if err != nil || decision.Allowed != allowed {
			t.Fatalf("action=%s allowed=%v reason=%s error=%v", action, decision.Allowed, decision.Reason, err)
		}
	}
	check("run", true)
	policy = nextDepartmentAgentPolicy(policy, []DepartmentAgentPolicyEntry{{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"history.read", "cancel"}}})
	check("run", false)
	check("history.read", true)
	policy = nextDepartmentAgentPolicy(policy, []DepartmentAgentPolicyEntry{{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run", "history.read", "cancel"}}})
	check("run", false) // restored ceiling must not restore old subordinate source
	check("history.read", true)
	independent := snapshot.Grants[0]
	independent.ID, independent.DepartmentAgentActionVersion = "company-issued-run", 0
	snapshot.Grants = append(snapshot.Grants, independent)
	check("run", true)
	explicitDeny := independent
	explicitDeny.ID, explicitDeny.Effect, explicitDeny.DepartmentAgentActionVersion = "run-denied", "deny", 999
	snapshot.Grants = append(snapshot.Grants, explicitDeny)
	check("run", false) // a denial is never ignored as an obsolete source
	policy = nextDepartmentAgentPolicy(policy, nil)
	check("cancel", true) // existing cancellation remains available for recovery
	snapshot.Grants = slices.DeleteFunc(snapshot.Grants, func(g Grant) bool { return g.Action == "cancel" })
	check("cancel", false)
}

func TestDepartmentAgentGrantInheritsApprovedWindowAndRejectsExpansion(t *testing.T) {
	now := time.Now().UTC()
	start, expiry := now.Add(time.Minute), now.Add(time.Hour)
	policy := nextDepartmentAgentPolicy(DepartmentAgentPolicy{TenantID: "company", DepartmentID: "department"}, []DepartmentAgentPolicyEntry{{ApplicationID: "application", InstallationID: "installed-agent", Actions: []string{"run"}, Validity: Validity{StartsAt: &start, ExpiresAt: &expiry}}})
	grant := Grant{ApplicationID: "application", AgentInstanceID: "installed-agent", Action: "run", Effect: "allow", DepartmentAgentActionVersion: 999}
	entry, err := constrainGrantToDepartmentPolicy(&grant, &policy, now)
	if err != nil || entry == nil || grant.StartsAt == nil || !grant.StartsAt.Equal(start) || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(expiry) || grant.DepartmentAgentActionVersion != 0 {
		t.Fatal("grant did not inherit the company's window and discard submitted source version", err)
	}
	extended := expiry.Add(time.Second)
	grant.ExpiresAt = &extended
	if _, err := constrainGrantToDepartmentPolicy(&grant, &policy, now); err != ErrPermissionDenied {
		t.Fatal("grant could extend beyond company ceiling", err)
	}
	grant.Action, grant.ExpiresAt = "history.share", nil
	if _, err := constrainGrantToDepartmentPolicy(&grant, &policy, now); err != ErrPermissionDenied {
		t.Fatal("unapproved sensitive action accepted", err)
	}
	grant.Effect = "deny"
	if _, err := constrainGrantToDepartmentPolicy(&grant, &policy, now); err != nil {
		t.Fatal("company ceiling prevented a protective denial", err)
	}
}

func TestDepartmentAgentPolicyPeriodChangeDoesNotReviveSubordinateGrant(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	expiry := now.Add(time.Hour)
	entry := DepartmentAgentPolicyEntry{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run"}, Validity: Validity{ExpiresAt: &expiry}}
	policy := nextDepartmentAgentPolicy(DepartmentAgentPolicy{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID}, []DepartmentAgentPolicyEntry{entry})
	snapshot.Grants[0].DepartmentAgentActionVersion = policy.Entries[0].ActionVersions["run"]
	newExpiry := expiry.Add(time.Hour)
	entry.ExpiresAt = &newExpiry
	policy = nextDepartmentAgentPolicy(policy, []DepartmentAgentPolicyEntry{entry})
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{policy}
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil || decision.Allowed {
		t.Fatal("changed approval term revived an old subordinate source", decision, err)
	}
}

func TestDepartmentAgentObsoleteSourceCannotRemoveDataDenial(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	policy := nextDepartmentAgentPolicy(DepartmentAgentPolicy{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID}, []DepartmentAgentPolicyEntry{{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"history.read"}}})
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{policy}
	deny := snapshot.Grants[2]
	deny.ID, deny.Effect, deny.DepartmentAgentActionVersion = "history-denied", "deny", 999
	snapshot.Grants = append(snapshot.Grants, deny)
	plan, err := CompileResourceDataPlan(snapshot, "history.read", query.Scope, now)
	if err != nil || len(plan.Allow) != 1 || len(plan.Deny) != 1 {
		t.Fatal("data projection dropped a protective denial because its source version was obsolete", plan, err)
	}
}

func departmentAgentPermissionFixture(now time.Time) (PermissionSnapshot, PermissionQuery) {
	scope := ManagementScope{Type: "application", TenantID: "company", DepartmentID: "department", ApplicationID: "application"}
	snapshot := PermissionSnapshot{Mode: "v2", Principal: Principal{Type: PrincipalUser, ID: "member", TenantID: scope.TenantID, IsActive: true}, Memberships: []Membership{{ID: "member-department", SubjectID: "member", Scope: scope, Status: "active", Revision: 1}}, Bindings: []RoleBinding{{ID: "member-role", SubjectID: "member", RoleCode: "fixture-user", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1}}, Roles: []RoleDefinition{{Code: "fixture-user", Version: 1, ScopeTypes: []string{"application"}, Actions: []string{"run", "cancel", "history.read", "model.generate"}}}}
	for _, action := range []string{"run", "cancel", "history.read"} {
		snapshot.Grants = append(snapshot.Grants, Grant{ID: "member-" + action, SubjectType: PrincipalUser, SubjectID: "member", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: "installed-agent", ResourceType: "agent_installation", ResourceID: "installed-agent", Action: action, Effect: "allow", Status: "active", Revision: 1, DataScope: DataScope{Type: "owner"}})
	}
	return snapshot, PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "installed-agent", Now: now}
}

func TestDepartmentAgentCeilingDoesNotCreatePersonalAuthority(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	check := func(want bool, reason string) {
		t.Helper()
		decision, err := EvaluatePermission(snapshot, query)
		if err != nil || decision.Allowed != want || reason != "" && decision.Reason != reason {
			t.Fatalf("allowed=%v reason=%s error=%v", decision.Allowed, decision.Reason, err)
		}
	}
	check(true, "") // pre-migration department retains its old explicit grants
	policy := DepartmentAgentPolicy{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, Revision: 1, EntriesDigest: departmentAgentEntriesDigest(nil), Entries: []DepartmentAgentPolicyEntry{}}
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{policy}
	check(false, "DEPARTMENT_AGENT_NOT_APPROVED")
	entry := DepartmentAgentPolicyEntry{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run", "history.read"}}
	snapshot.DepartmentAgentPolicies[0].Entries = []DepartmentAgentPolicyEntry{entry}
	check(true, "")
	snapshot.Grants = nil
	check(false, "RESOURCE_GRANT_REQUIRED")
	snapshot, query = departmentAgentPermissionFixture(now)
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{policy}
	snapshot.DepartmentAgentPolicies[0].Entries = []DepartmentAgentPolicyEntry{entry}
	snapshot.Bindings = nil
	check(false, "ROLE_REQUIRED")
}

func TestDepartmentAgentCeilingScopeExpiryAndRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	base, query := departmentAgentPermissionFixture(now)
	entry := DepartmentAgentPolicyEntry{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run", "history.read"}}
	for _, test := range []struct {
		name, reason string
		change       func(*PermissionSnapshot, *DepartmentAgentPolicyEntry)
	}{
		{"not-approved", "DEPARTMENT_AGENT_NOT_APPROVED", func(_ *PermissionSnapshot, e *DepartmentAgentPolicyEntry) { e.InstallationID = "another-agent" }},
		{"wrong-application", "DEPARTMENT_AGENT_NOT_APPROVED", func(_ *PermissionSnapshot, e *DepartmentAgentPolicyEntry) { e.ApplicationID = "another-application" }},
		{"operation-removed", "DEPARTMENT_AGENT_ACTION_DENIED", func(_ *PermissionSnapshot, e *DepartmentAgentPolicyEntry) { e.Actions = []string{"history.read"} }},
		{"expired", "DEPARTMENT_AGENT_INACTIVE", func(_ *PermissionSnapshot, e *DepartmentAgentPolicyEntry) { e.ExpiresAt = &now }},
		{"not-started", "DEPARTMENT_AGENT_INACTIVE", func(_ *PermissionSnapshot, e *DepartmentAgentPolicyEntry) {
			future := now.Add(time.Minute)
			e.StartsAt = &future
		}},
		{"company-membership-is-not-department-membership", "DEPARTMENT_MEMBERSHIP_REQUIRED", func(s *PermissionSnapshot, _ *DepartmentAgentPolicyEntry) {
			s.Memberships = []Membership{{ID: "company-member", SubjectID: s.Principal.ID, Scope: ManagementScope{Type: "tenant", TenantID: s.Principal.TenantID}, Status: "active", Revision: 1}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, candidate := base, entry
			test.change(&snapshot, &candidate)
			snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, Revision: 1, Entries: []DepartmentAgentPolicyEntry{candidate}}}
			decision, err := EvaluatePermission(snapshot, query)
			if err != nil || decision.Allowed || decision.Reason != test.reason {
				t.Fatal("ceiling did not constrain existing allow", decision, err)
			}
		})
	}
	base.DepartmentAgentPolicies = []DepartmentAgentPolicy{{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, Revision: 1}}
	query.Action = "cancel"
	if decision, err := EvaluatePermission(base, query); err != nil || !decision.Allowed {
		t.Fatal("revocation stranded cancellation despite existing role and grant", err)
	}
	base.Grants = nil
	if decision, err := EvaluatePermission(base, query); err != nil || decision.Allowed {
		t.Fatal("recovery created a new cancellation entitlement", err)
	}
}

func TestDepartmentAgentCeilingConstrainsDependenciesAndMachine(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	query.Action, query.ResourceType, query.ResourceID = "model.generate", "model", "model-deployment"
	query.Scope.Type, query.Scope.ResourceID = "agent_installation", "installed-agent"
	snapshot.Grants = []Grant{{ID: "model-grant", SubjectType: PrincipalUser, SubjectID: snapshot.Principal.ID, TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID, AgentInstanceID: query.Scope.ResourceID, ResourceType: "model", ResourceID: query.ResourceID, Action: query.Action, Effect: "allow", Status: "active", Revision: 1, DataScope: DataScope{Type: "owner"}}}
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, Revision: 1, Entries: []DepartmentAgentPolicyEntry{{ApplicationID: query.Scope.ApplicationID, InstallationID: query.Scope.ResourceID, Actions: []string{"run"}}}}}
	if decision, err := EvaluatePermission(snapshot, query); err != nil || decision.Allowed || decision.Reason != "DEPARTMENT_AGENT_ACTION_DENIED" {
		t.Fatal("dependency escaped Agent ceiling", decision, err)
	}
	snapshot.DepartmentAgentPolicies[0].Entries[0].Actions = []string{"run", "model.generate"}
	if decision, err := EvaluatePermission(snapshot, query); err != nil || !decision.Allowed {
		t.Fatal("approved dependency with exact personal grant unavailable", err)
	}
	snapshot.Principal.Type, snapshot.Grants[0].SubjectType = PrincipalServicePrincipal, PrincipalServicePrincipal
	snapshot.Memberships, snapshot.Bindings = nil, nil
	if decision, err := EvaluatePermission(snapshot, query); err != nil || !decision.Allowed {
		t.Fatal("approved machine resource unavailable", err)
	}
	snapshot.DepartmentAgentPolicies[0].Entries = nil
	if decision, err := EvaluatePermission(snapshot, query); err != nil || decision.Allowed {
		t.Fatal("machine escaped withdrawn Agent ceiling", err)
	}
}

func TestDepartmentAgentCeilingBindsNaturalExpiryAndDataLists(t *testing.T) {
	now := time.Now().UTC()
	snapshot, query := departmentAgentPermissionFixture(now)
	expiry := now.Add(time.Minute)
	entry := DepartmentAgentPolicyEntry{ApplicationID: query.Scope.ApplicationID, InstallationID: query.ResourceID, Actions: []string{"run", "history.read"}, Validity: Validity{ExpiresAt: &expiry}}
	snapshot.DepartmentAgentPolicies = []DepartmentAgentPolicy{{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, Revision: 1, EntriesDigest: departmentAgentEntriesDigest([]DepartmentAgentPolicyEntry{entry}), Entries: []DepartmentAgentPolicyEntry{entry}}}
	before, err := EffectivePermissionSnapshotDigest(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := EffectivePermissionSnapshotDigest(snapshot, expiry)
	if err != nil || before == after {
		t.Fatal("entry expiry left caller permission version unchanged", err)
	}
	plan, err := CompileResourceDataPlan(snapshot, "history.read", query.Scope, now)
	if err != nil || len(plan.Allow) != 1 {
		t.Fatal("approved history disappeared", err)
	}
	plan, err = CompileResourceDataPlan(snapshot, "history.read", query.Scope, expiry)
	if err != nil || len(plan.Allow) != 0 {
		t.Fatal("data list bypassed expired department policy", err)
	}
}
