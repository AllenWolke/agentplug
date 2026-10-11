package identity

import (
	"testing"
	"time"
)

func TestResourceReadPlanMatchesObjectDecisions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*PermissionSnapshot, time.Time)
	}{
		{"owner", func(*PermissionSnapshot, time.Time) {}},
		{"explicit set", func(s *PermissionSnapshot, _ time.Time) {
			s.Grants[0].DataScope = DataScope{Type: "explicit_set", IDs: []string{"object-2", "object-3"}}
		}},
		{"organization with selective deny", func(s *PermissionSnapshot, _ time.Time) {
			s.Grants[0].DataScope = DataScope{Type: "approved_organization"}
			deny := s.Grants[0]
			deny.ID, deny.Effect, deny.DataScope = "deny", "deny", DataScope{Type: "explicit_set", IDs: []string{"object-2"}}
			s.Grants = append(s.Grants, deny)
		}},
		{"owner deny leaves other owners", func(s *PermissionSnapshot, _ time.Time) {
			deny := s.Grants[0]
			deny.ID, deny.Effect = "deny", "deny"
			s.Grants[0].DataScope = DataScope{Type: "approved_organization"}
			s.Grants = append(s.Grants, deny)
		}},
		{"multiple installation grant", func(s *PermissionSnapshot, _ time.Time) {
			other := s.Grants[0]
			other.ID, other.AgentInstanceID, other.ResourceID, other.DataScope = "other", "j", "j", DataScope{Type: "approved_organization"}
			s.Grants = append(s.Grants, other)
		}},
		{"installation role excludes other", func(s *PermissionSnapshot, _ time.Time) {
			s.Bindings[0].Scope.Type, s.Bindings[0].Scope.ResourceID = "agent_installation", "i"
			other := s.Grants[0]
			other.ID, other.ResourceID = "other", "j"
			s.Grants = append(s.Grants, other)
		}},
		{"no role", func(s *PermissionSnapshot, _ time.Time) { s.Bindings = nil }},
		{"no member", func(s *PermissionSnapshot, _ time.Time) { s.Memberships = nil }},
		{"management only", func(s *PermissionSnapshot, _ time.Time) {
			s.Bindings[0].RoleCode, s.Bindings[0].Scope = "super_admin", ManagementScope{Type: "global"}
		}},
		{"expired", func(s *PermissionSnapshot, now time.Time) { s.Grants[0].ExpiresAt = &now }},
		{"future", func(s *PermissionSnapshot, now time.Time) {
			future := now.Add(time.Hour)
			s.Grants[0].StartsAt = &future
		}},
		{"disabled", func(s *PermissionSnapshot, _ time.Time) { s.Principal.IsActive = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, q := permissionFixture()
			q.Action, s.Grants[0].Action = "history.read", "history.read"
			tc.change(&s, q.Now)
			plan, err := CompileResourceDataPlan(s, q.Action, q.Scope, q.Now)
			if err != nil {
				t.Fatal(err)
			}
			for _, installation := range []string{"i", "j"} {
				for index, owner := range []string{"u", "other", "other"} {
					id := []string{"object-1", "object-2", "object-3"}[index]
					scope := q.Scope
					scope.Type, scope.ResourceID = "agent_installation", installation
					object := DataObject{ID: id, OwnerID: owner, Scope: scope}
					query := q
					query.Scope, query.ResourceID, query.Object = scope, installation, &object
					decision, err := EvaluatePermission(s, query)
					if err != nil {
						t.Fatal(err)
					}
					matches := func(clauses []ResourceDataClause) bool {
						for _, clause := range clauses {
							if clause.ResourceID == installation && clause.DataScope.Allows(s.Principal.ID, q.Scope, object) {
								return true
							}
						}
						return false
					}
					if got := matches(plan.Allow) && !matches(plan.Deny); got != decision.Allowed {
						t.Fatalf("filter decision mismatch installation=%s object=%s got=%v decision=%+v", installation, id, got, decision)
					}
				}
			}
		})
	}
}
