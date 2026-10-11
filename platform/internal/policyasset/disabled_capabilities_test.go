package policyasset

import "testing"

func TestExplicitEmptyCapabilityListsPublishAsDenyAll(t *testing.T) {
	for typ, content := range map[AssetType]string{
		AssetTool:      `{"allowed_tools":[],"require_confirmation":[]}`,
		AssetKnowledge: `{"allowed_scopes":[],"require_references":false,"allow_partial_degraded":false,"allow_replay":false}`,
	} {
		if err := validateAssetContent(typ, []byte(content)); err != nil {
			t.Fatalf("disabled %s: %v", typ, err)
		}
	}
	s := Snapshot{Tool: ToolPolicy{AllowedTools: []string{}}, Knowledge: KnowledgePolicy{AllowedScopes: []string{}}}
	if s.AllowsTool("utc.clock") || s.AllowsKnowledgeScope("any-source") {
		t.Fatal("disabled capability allowed a resource")
	}
}

func TestMissingCapabilityListsCannotBecomePublishedPolicy(t *testing.T) {
	for typ, content := range map[AssetType]string{
		AssetTool:      `{"require_confirmation":[]}`,
		AssetKnowledge: `{"require_references":false}`,
	} {
		if err := validateAssetContent(typ, []byte(content)); err == nil {
			t.Fatalf("missing %s list accepted", typ)
		}
	}
}
