package identity

import "testing"

func TestReviewProjectionRequiresRoleGrantAndUsableDataRange(t *testing.T) {
	for _, name := range []string{"authorized", "role-only", "grant-only", "owner-only", "deny-all", "deny-selected", "missing-member", "expired"} {
		t.Run(name, func(t *testing.T) {
			s, q := permissionFixture()
			s.Bindings[0].RoleCode = "reviewer"
			s.Grants[0].Action, s.Grants[0].DataScope.Type = "business.review", "approved_organization"
			want := name == "authorized"
			switch name {
			case "role-only":
				s.Grants = nil
			case "grant-only":
				s.Bindings = nil
			case "owner-only":
				s.Grants[0].DataScope.Type = "owner"
			case "missing-member":
				s.Memberships = nil
			case "expired":
				s.Grants[0].ExpiresAt = &q.Now
			case "deny-all":
				deny := s.Grants[0]
				deny.ID, deny.Effect = "deny", "deny"
				s.Grants = append(s.Grants, deny)
			case "deny-selected":
				s.Grants[0].DataScope = DataScope{Type: "explicit_set", IDs: []string{"selected"}}
				deny := s.Grants[0]
				deny.ID, deny.Effect = "deny", "deny"
				s.Grants = append(s.Grants, deny)
			}
			plan, err := CompileResourceDataPlan(s, "business.review", q.Scope, q.Now)
			if err != nil {
				t.Fatal(err)
			}
			if got := reviewDataOpportunity(plan); got != want {
				t.Fatal("unexpected review qualification", got, want)
			}
		})
	}
}
