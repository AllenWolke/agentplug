package identity

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func migrationMappingFixture(t *testing.T) (MigrationSource, MigrationMapping, PermissionQuery, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	app := ManagementScope{Type: "application", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application"}
	snapshot := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: "user", TenantID: "tenant", IsActive: true, Revision: 1, Roles: []string{"platform_admin"}}, Mode: "legacy", Roles: BuiltinRoleDefinitions(), Memberships: []Membership{}, Bindings: []RoleBinding{}, Grants: []Grant{{ID: "allow", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "installation", SubjectType: PrincipalUser, SubjectID: "user", Action: "run", Effect: "allow", Status: "active", Revision: 1}}}
	source := MigrationSource{Snapshot: snapshot, AuthenticationDigest: permissionHash([]byte("actual-credential-facts"))}
	source.SourceDigest, _ = migrationSourceDigest(source)
	var target PermissionSnapshot
	raw, _ := json.Marshal(snapshot)
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	target.Mode = "v2"
	target.Memberships = []Membership{{ID: "member", SubjectID: "user", Scope: app, Status: "active", Revision: 1}}
	target.Bindings = []RoleBinding{{ID: "operator", SubjectID: "user", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "reviewed-job"}}
	target.Grants[0].ResourceType, target.Grants[0].ResourceID = "agent_installation", "installation"
	target.Grants[0].DataScope = DataScope{Type: "owner"}
	q := PermissionQuery{Action: "run", Scope: ManagementScope{Type: "agent_installation", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ResourceID: "installation"}, ResourceType: "agent_installation", ResourceID: "installation"}
	return source, MigrationMapping{ExpectedSourceDigest: source.SourceDigest, Basis: "verified job and installation mapping", Target: target}, q, now
}

func TestMigrationMappingFullFactsAndActualLegacyShadow(t *testing.T) {
	source, mapping, q, now := migrationMappingFixture(t)
	plan, err := PreviewMigrationMapping(source, mapping, []PermissionQuery{q}, now)
	if err != nil || len(plan.Issues) != 0 || len(plan.Differences) != 3 || len(plan.Samples) != 1 || plan.Samples[0].Classification != "allowed_both_compare_ranges" || !plan.Samples[0].ScopeOnly {
		t.Fatal(plan, err)
	}
	for _, diff := range plan.Differences {
		if diff.Kind == "grant" && (diff.Change != "changed" || diff.Before == nil || diff.After == nil) {
			t.Fatal("grant data range diff missing", diff)
		}
	}
	plan.Target.Grants[0].DataScope.Type = "approved_organization"
	if mapping.Target.Grants[0].DataScope.Type != "owner" || source.Snapshot.Grants[0].ResourceType != "" {
		t.Fatal("preview mutated inputs")
	}
	until := now.Add(-time.Minute)
	source.Snapshot.Grants[0].ExpiresAt = &until
	source.SourceDigest, _ = migrationSourceDigest(source)
	mapping.ExpectedSourceDigest = source.SourceDigest
	mapping.Target.Grants[0].ExpiresAt = &until
	plan, err = PreviewMigrationMapping(source, mapping, []PermissionQuery{q}, now)
	if err != nil || plan.Samples[0].Classification != "permission_removed" || !plan.Samples[0].Old.Allowed || plan.Samples[0].Target.Reason != "RESOURCE_GRANT_REQUIRED" {
		t.Fatal("legacy expiry semantics were fabricated", plan, err)
	}
}

func TestMigrationMappingRejectsStaleAndImmutableChanges(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*MigrationSource, *MigrationMapping)
	}{
		{"source", func(s *MigrationSource, _ *MigrationMapping) { s.Snapshot.Principal.Revision++ }},
		{"expected", func(_ *MigrationSource, m *MigrationMapping) { m.ExpectedSourceDigest = "stale" }},
		{"subject", func(_ *MigrationSource, m *MigrationMapping) { m.Target.Principal.ID = "other" }},
		{"disabled", func(_ *MigrationSource, m *MigrationMapping) { m.Target.Principal.IsActive = false }},
		{"roles", func(_ *MigrationSource, m *MigrationMapping) { m.Target.Roles[0].Actions = []string{"run"} }},
		{"binding_subject", func(_ *MigrationSource, m *MigrationMapping) { m.Target.Bindings[0].SubjectID = "other" }},
		{"foreign", func(_ *MigrationSource, m *MigrationMapping) { m.Target.Grants[0].TenantID = "other" }},
		{"duplicate", func(_ *MigrationSource, m *MigrationMapping) {
			m.Target.Grants = append(m.Target.Grants, m.Target.Grants[0])
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			s, m, _, now := migrationMappingFixture(t)
			change.mutate(&s, &m)
			if _, err := PreviewMigrationMapping(s, m, nil, now); err == nil {
				t.Fatal("unsafe mapping accepted")
			}
		})
	}
	s, m, _, now := migrationMappingFixture(t)
	m.ExpectedSourceDigest = "stale"
	if _, err := PreviewMigrationMapping(s, m, nil, now); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal(err)
	}
}

func TestMigrationMappingDeniesRevokedAndAdminRequireExplicitReview(t *testing.T) {
	source, mapping, q, now := migrationMappingFixture(t)
	deny := source.Snapshot.Grants[0]
	deny.ID, deny.Effect = "deny", "deny"
	revoked := deny
	revoked.ID, revoked.Status = "revoked", "revoked"
	source.Snapshot.Grants = append(source.Snapshot.Grants, deny, revoked)
	source.SourceDigest, _ = migrationSourceDigest(source)
	mapping.ExpectedSourceDigest = source.SourceDigest
	plan, err := PreviewMigrationMapping(source, mapping, []PermissionQuery{q}, now)
	if err != nil || !migrationHasIssue(plan, "DENY_MUST_BE_PRESERVED") || !migrationHasIssue(plan, "REVOKED_GRANT_MUST_BE_PRESERVED") || !migrationHasIssue(plan, "PERMISSION_ADDITION_REQUIRES_REVIEW") {
		t.Fatal("protected facts silently dropped", plan, err)
	}
	converted := deny
	converted.ResourceType, converted.ResourceID, converted.DataScope = "agent_installation", "installation", DataScope{Type: "approved_organization"}
	mapping.Target.Grants = append(mapping.Target.Grants, converted, revoked)
	plan, err = PreviewMigrationMapping(source, mapping, []PermissionQuery{q}, now)
	if err != nil || len(plan.Issues) != 0 || plan.Samples[0].Target.Allowed || plan.Samples[0].Target.Reason != "EXPLICIT_DENY" {
		t.Fatal("conservative deny enrichment rejected or bypassed", plan, err)
	}
	mapping.Target.Grants[1].DataScope = DataScope{Type: "owner"}
	plan, err = PreviewMigrationMapping(source, mapping, nil, now)
	if err != nil || !migrationHasIssue(plan, "DENY_MUST_BE_PRESERVED") {
		t.Fatal("legacy deny narrowed to owner", plan, err)
	}
	mapping.Target.Bindings = append(mapping.Target.Bindings, RoleBinding{ID: "admin", SubjectID: "user", RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1})
	management := PermissionQuery{Action: "principal.read", Scope: ManagementScope{Type: "global"}}
	plan, err = PreviewMigrationMapping(source, mapping, []PermissionQuery{management}, now)
	if err != nil || !migrationHasIssue(plan, "VERIFIED_ADMIN_APPOINTMENT_REQUIRED") || plan.Samples[0].Old != nil || plan.Samples[0].Classification != "unverified" || !plan.Samples[0].Target.Allowed || plan.Samples[0].UnverifiedReason != "LEGACY_MANAGEMENT_ROUTE_PROBE_REQUIRED" {
		t.Fatal("administrator inferred from old role or basis", plan, err)
	}
}

func migrationHasIssue(plan MigrationMappingPreview, code string) bool {
	for _, issue := range plan.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestMigrationMappingDisabledAndDenyTimeBoundaries(t *testing.T) {
	s, m, q, now := migrationMappingFixture(t)
	s.Snapshot.Principal.IsActive = false
	s.SourceDigest, _ = migrationSourceDigest(s)
	m.ExpectedSourceDigest, m.Target.Principal.IsActive = s.SourceDigest, false
	plan, err := PreviewMigrationMapping(s, m, []PermissionQuery{q}, now)
	if err != nil || plan.Samples[0].Classification != "denied_both_compare_reasons" || plan.Samples[0].Target.Reason != "PRINCIPAL_DISABLED" {
		t.Fatal("disabled source not retained", plan.Samples, err)
	}
	s, m, q, now = migrationMappingFixture(t)
	later := now.Add(time.Hour)
	s.Snapshot.Grants[0].Effect, s.Snapshot.Grants[0].ExpiresAt = "deny", &later
	s.SourceDigest, _ = migrationSourceDigest(s)
	m.ExpectedSourceDigest = s.SourceDigest
	m.Target.Grants[0].Effect, m.Target.Grants[0].ExpiresAt = "deny", &later
	m.Target.Grants[0].DataScope = DataScope{Type: "approved_organization"}
	plan, err = PreviewMigrationMapping(s, m, []PermissionQuery{q}, now)
	if err != nil || !migrationHasIssue(plan, "LEGACY_DENY_TIME_BOUNDARY_REQUIRES_REVIEW") || plan.Samples[0].Target.Allowed {
		t.Fatal("future deny expiry was hidden", plan.Issues, err)
	}
}
