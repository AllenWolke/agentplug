package identity

import (
	"testing"
	"time"
)

func permissionFixture() (PermissionSnapshot, PermissionQuery) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	scope := ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	snapshot := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Mode: "v2", Roles: BuiltinRoleDefinitions(), Memberships: []Membership{{ID: "m", SubjectID: "u", Scope: scope, Status: "active", Revision: 1}}, Bindings: []RoleBinding{{ID: "b", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "s"}}, Grants: []Grant{{ID: "g", SubjectType: PrincipalUser, SubjectID: "u", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "agent_installation", ResourceID: "i", Action: "run", Effect: "allow", Status: "active", Revision: 1, DataScope: DataScope{Type: "owner"}, SourceID: "s"}}}
	query := PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "i", Now: now}
	return snapshot, query
}

func TestManagementScopeBoundaries(t *testing.T) {
	for _, invalid := range []ManagementScope{{Type: "global", TenantID: "t"}, {Type: "application", TenantID: "t", ApplicationID: "a"}, {Type: "tenant", TenantID: "*"}, {Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "i"}, {Type: "unknown"}} {
		if invalid.Validate() == nil {
			t.Fatalf("accepted invalid scope: %+v", invalid)
		}
	}
	parent := ManagementScope{Type: "department", TenantID: "t", DepartmentID: "d"}
	child := ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	if !parent.Contains(child) || child.Contains(parent) {
		t.Fatal("scope hierarchy reversed")
	}
	child.TenantID = "other"
	if parent.Contains(child) {
		t.Fatal("cross-tenant scope accepted")
	}
}

func TestPermissionConjunctiveBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*PermissionSnapshot, *PermissionQuery)
		allowed bool
		reason  string
	}{
		{"allowed", func(*PermissionSnapshot, *PermissionQuery) {}, true, "EXPLICIT_ALLOW"},
		{"no role", func(s *PermissionSnapshot, q *PermissionQuery) { s.Bindings = nil }, false, "ROLE_REQUIRED"},
		{"no member", func(s *PermissionSnapshot, q *PermissionQuery) { s.Memberships = nil }, false, "ROLE_REQUIRED"},
		{"no grant", func(s *PermissionSnapshot, q *PermissionQuery) { s.Grants = nil }, false, "RESOURCE_GRANT_REQUIRED"},
		{"wrong resource", func(s *PermissionSnapshot, q *PermissionQuery) { q.ResourceID = "other" }, false, "RESOURCE_GRANT_REQUIRED"},
		{"disabled", func(s *PermissionSnapshot, q *PermissionQuery) { s.Principal.IsActive = false }, false, "PRINCIPAL_DISABLED"},
		{"cross tenant", func(s *PermissionSnapshot, q *PermissionQuery) { q.Scope.TenantID = "other" }, false, "TENANT_MISMATCH"},
		{"unknown action", func(s *PermissionSnapshot, q *PermissionQuery) { q.Action = "new.action" }, false, "UNKNOWN_ACTION"},
		{"wrong role version", func(s *PermissionSnapshot, q *PermissionQuery) { s.Bindings[0].RoleVersion = 999 }, false, "ROLE_REQUIRED"},
		{"explicit deny", func(s *PermissionSnapshot, q *PermissionQuery) {
			g := s.Grants[0]
			g.ID = "deny"
			g.Effect = "deny"
			s.Grants = append(s.Grants, g)
		}, false, "EXPLICIT_DENY"},
		{"grant expires now", func(s *PermissionSnapshot, q *PermissionQuery) { s.Grants[0].ExpiresAt = &q.Now }, false, "RESOURCE_GRANT_REQUIRED"},
		{"future grant", func(s *PermissionSnapshot, q *PermissionQuery) {
			future := q.Now.Add(time.Hour)
			s.Grants[0].StartsAt = &future
		}, false, "RESOURCE_GRANT_REQUIRED"},
		{"role expires now", func(s *PermissionSnapshot, q *PermissionQuery) { s.Bindings[0].ExpiresAt = &q.Now }, false, "ROLE_REQUIRED"},
		{"owner mismatch", func(s *PermissionSnapshot, q *PermissionQuery) {
			q.Object = &DataObject{ID: "o", OwnerID: "other", Scope: q.Scope}
		}, false, "RESOURCE_GRANT_REQUIRED"},
		{"matching owner", func(s *PermissionSnapshot, q *PermissionQuery) {
			q.Object = &DataObject{ID: "o", OwnerID: "u", Scope: q.Scope}
		}, true, "EXPLICIT_ALLOW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, q := permissionFixture()
			tt.change(&s, &q)
			got, err := EvaluatePermission(s, q)
			if err != nil || got.Allowed != tt.allowed || got.Reason != tt.reason {
				t.Fatalf("decision %+v error %v", got, err)
			}
		})
	}
}

func TestAdministratorHasNoDefaultDataAccess(t *testing.T) {
	s, q := permissionFixture()
	s.Bindings[0].RoleCode = "super_admin"
	s.Bindings[0].Scope = ManagementScope{Type: "global"}
	s.Memberships = nil
	got, err := EvaluatePermission(s, q)
	if err != nil || got.Allowed {
		t.Fatal("super administrator bypassed data role", got, err)
	}
	q.Action = "administrator.appoint"
	got, err = EvaluatePermission(s, q)
	if err != nil || !got.Allowed {
		t.Fatal("super administrator cannot manage", got, err)
	}
}

func TestMachineAndReviewerBoundaries(t *testing.T) {
	s, q := permissionFixture()
	s.Principal.Type = PrincipalServicePrincipal
	s.Bindings = nil
	s.Memberships = nil
	s.Grants[0].SubjectType = PrincipalServicePrincipal
	got, err := EvaluatePermission(s, q)
	if err != nil || !got.Allowed {
		t.Fatal(got, err)
	}
	q.Action = "authorization.change"
	got, err = EvaluatePermission(s, q)
	if err != nil || got.Allowed || got.Reason != "MACHINE_MANAGEMENT_DENIED" {
		t.Fatal(got, err)
	}
	s, q = permissionFixture()
	s.Bindings[0].RoleCode = "reviewer"
	s.Grants[0].Action = "business.review"
	s.Grants[0].DataScope = DataScope{Type: "assigned_task"}
	q.Action = "business.review"
	q.Scope.Type, q.Scope.ResourceID = "agent_installation", q.ResourceID
	q.Object = &DataObject{ID: "report", OwnerID: "u", AssignedTo: []string{"u"}, Scope: q.Scope}
	object := *q.Object
	s.Assignments = []TaskAssignment{{ID: "assignment", SubjectID: "u", TaskID: "report", Action: q.Action, Scope: q.Scope, Status: "active", Revision: 1, SourceID: "test", TaskObject: &object}}
	got, err = EvaluatePermission(s, q)
	if err != nil || got.Reason != "SELF_REVIEW_DENIED" {
		t.Fatal(got, err)
	}
	q.Object.OwnerID = "other"
	object.OwnerID = "other"
	got, err = EvaluatePermission(s, q)
	if err != nil || !got.Allowed {
		t.Fatal(got, err)
	}
}

func TestMultipleGrantSourcesAndApplicationRoles(t *testing.T) {
	s, q := permissionFixture()
	second := s.Grants[0]
	second.ID = "g2"
	second.SourceID = "second"
	s.Grants = append(s.Grants, second)
	s.Grants[0].Status = "revoked"
	got, err := EvaluatePermission(s, q)
	if err != nil || !got.Allowed || len(got.GrantIDs) != 1 || got.GrantIDs[0] != "g2" {
		t.Fatal(got, err)
	}
	s.Grants[1].Status = "revoked"
	got, err = EvaluatePermission(s, q)
	if err != nil || got.Allowed {
		t.Fatal(got, err)
	}
	s, q = permissionFixture()
	q.Scope.ApplicationID = "b"
	s.Memberships = append(s.Memberships, Membership{ID: "mb", SubjectID: "u", Scope: q.Scope, Status: "active"})
	b := s.Bindings[0]
	b.ID = "bb"
	b.Scope = q.Scope
	b.RoleCode = "reviewer"
	s.Bindings = append(s.Bindings, b)
	got, err = EvaluatePermission(s, q)
	if err != nil || got.Reason != "ROLE_REQUIRED" {
		t.Fatal("application role leaked", got, err)
	}
}

func TestDelegationRequiresCompleteSingleBoundary(t *testing.T) {
	_, q := permissionFixture()
	end := q.Now.Add(time.Hour)
	d := Delegation{ID: "d", SubjectID: "admin", Scope: q.Scope, Roles: []string{"operator"}, Actions: []string{"run"}, Resources: []string{"i"}, DataScopeTypes: []string{"owner"}, ManagementActions: []string{"authorization.change"}, MaxDurationSeconds: 3600, Validity: Validity{ExpiresAt: &end}, Status: "active"}
	valid := Validity{ExpiresAt: &end}
	check := func(d Delegation, role, action, resource string, v Validity) bool {
		return d.Covers("admin", "authorization.change", role, action, resource, q.Scope, DataScope{Type: "owner"}, v, q.Now)
	}
	if !check(d, "operator", "run", "i", valid) {
		t.Fatal("legal delegation denied")
	}
	if check(d, "super_admin", "run", "i", valid) || check(d, "reviewer", "run", "i", valid) || check(d, "operator", "run", "other", valid) || check(d, "operator", "run", "i", Validity{}) {
		t.Fatal("delegation boundary bypassed")
	}
	later := end.Add(time.Second)
	if check(d, "operator", "run", "i", Validity{ExpiresAt: &later}) {
		t.Fatal("grant outlived delegation")
	}
	d.Status = "revoked"
	if check(d, "operator", "run", "i", valid) {
		t.Fatal("revoked delegation accepted")
	}
}

func TestPresetsNeverDefaultSensitiveOrFutureResources(t *testing.T) {
	roles := BuiltinRoleDefinitions()
	publishedV1Roles := 0
	for _, role := range roles {
		if role.Version == 1 {
			publishedV1Roles++
		}
	}
	if publishedV1Roles != 11 {
		t.Fatal("incorrect human role catalogue")
	}
	for _, p := range BuiltinIdentityPresets() {
		if p.Version == 0 {
			t.Fatal("unversioned preset")
		}
		if p.SubjectType == PrincipalServicePrincipal && p.RoleCode != "" {
			t.Fatal("machine inherited human role")
		}
		for _, a := range p.ResourceActions {
			if a == "history.export" || a == "history.share" || a == "audit.content.read" {
				t.Fatal("sensitive default", p.Code)
			}
		}
	}
}

func TestPermissionDigestOrderAndVersion(t *testing.T) {
	s, _ := permissionFixture()
	g := s.Grants[0]
	g.ID = "second"
	s.Grants = append(s.Grants, g)
	a, err := PermissionSnapshotDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Grants[0], s.Grants[1] = s.Grants[1], s.Grants[0]
	b, _ := PermissionSnapshotDigest(s)
	if a != b {
		t.Fatal("digest depends on query order")
	}
	s.Bindings[0].Revision++
	c, _ := PermissionSnapshotDigest(s)
	if b == c {
		t.Fatal("digest ignored authorization change")
	}
}
