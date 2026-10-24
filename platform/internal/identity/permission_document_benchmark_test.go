package identity

import (
	"fmt"
	"testing"
)

func TestPublicActionMetadataCannotChangePermissionEvaluation(t *testing.T) {
	snapshot, query := permissionFixture()
	snapshot.Grants = nil
	actions := BuiltinPermissionActions()
	for i := range actions {
		actions[i].Management = true
		actions[i].ResourceType = ""
		if actions[i].DefaultDataScope != nil {
			actions[i].DefaultDataScope.Type = "approved_organization"
		}
	}
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil || decision.Allowed || decision.Reason != "RESOURCE_GRANT_REQUIRED" {
		t.Fatal("public catalogue mutation affected grant enforcement", decision, err)
	}
}

// Same fresh permission semantics as document filtering. This is a local
// allocation/CPU probe, never an authorization cache or live-service benchmark.
func BenchmarkKnowledgeDocumentPermission(b *testing.B) {
	for _, unrelated := range []int{0, 1000} {
		b.Run(fmt.Sprintf("unrelated-grants-%d", unrelated), func(b *testing.B) {
			snapshot, query := permissionFixture()
			query.Action, query.ResourceType, query.ResourceID = "knowledge.search", "knowledge", "kb"
			query.Scope = ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "i"}
			query.Object = &DataObject{ID: "doc", OwnerID: "u", Scope: query.Scope}
			grant := snapshot.Grants[0]
			grant.Action, grant.ResourceType, grant.ResourceID = query.Action, query.ResourceType, query.ResourceID
			snapshot.Grants = nil
			for i := 0; i < unrelated; i++ {
				other := grant
				other.ID, other.ResourceID = fmt.Sprint("other-", i), fmt.Sprint("kb-", i)
				snapshot.Grants = append(snapshot.Grants, other)
			}
			snapshot.Grants = append(snapshot.Grants, grant)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decision, err := EvaluatePermission(snapshot, query)
				if err != nil || !decision.Allowed {
					b.Fatal(decision, err)
				}
			}
		})
	}
}
