package policyasset

import (
	"encoding/json"
	"testing"
)

func TestReasoningModeIsPublishedAndExcludedFromEmbedding(t *testing.T) {
	policy := ModelPolicy{Provider: "deepseek", Model: "deepseek-flash", MaxTokens: 512}
	legacy, _ := json.Marshal(policy)
	_, oldHash, err := canonicalContent(AssetModel, legacy)
	if err != nil {
		t.Fatal(err)
	}
	policy.ReasoningMode = "disabled"
	configured, _ := json.Marshal(policy)
	_, newHash, err := canonicalContent(AssetModel, configured)
	if err != nil || oldHash == newHash {
		t.Fatal("reasoning change must invalidate publication content hash", err)
	}
	embedding, err := policy.ForEmbedding()
	if err != nil || embedding.ReasoningMode != "" || policy.ReasoningMode != "disabled" {
		t.Fatal("chat reasoning leaked into embedding or mutated published policy", err)
	}
	policy.ReasoningMode = "unreviewed-extension"
	invalid, _ := json.Marshal(policy)
	if _, _, err := canonicalContent(AssetModel, invalid); err == nil {
		t.Fatal("invalid reasoning mode was publishable")
	}
}

func TestReasoningEffortRequiresPublishedThinkingAndChangesContentHash(t *testing.T) {
	policy := ModelPolicy{Provider: "deepseek", Model: "deepseek-flash", MaxTokens: 512, ReasoningMode: "enabled"}
	var previous string
	for _, effort := range []string{"low", "high", "max"} {
		policy.ReasoningEffort = effort
		raw, _ := json.Marshal(policy)
		_, hash, err := canonicalContent(AssetModel, raw)
		if err != nil || hash == previous {
			t.Fatalf("effort %s was not independently bound to publication: %v", effort, err)
		}
		previous = hash
		embedding, err := policy.ForEmbedding()
		if err != nil || embedding.ReasoningEffort != "" || embedding.ReasoningMode != "" || policy.ReasoningEffort != effort {
			t.Fatal("reasoning effort leaked into embedding or mutated the source policy", err)
		}
	}
	for _, invalid := range []ModelPolicy{
		{ReasoningMode: "enabled", ReasoningEffort: "ultra"},
		{ReasoningMode: "disabled", ReasoningEffort: "max"},
		{ReasoningEffort: "max"},
	} {
		if invalid.ValidateReasoningMode() == nil {
			t.Fatal("unreviewable or contradictory reasoning effort accepted")
		}
	}
}
