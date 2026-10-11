package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublishedEmbeddingTargetIsCompleteAndPreservesPrimary(t *testing.T) {
	primary := ModelPolicy{Provider: "chat-provider", Model: "chat", ModelVersionID: "chat-v1", MaxTokens: 512, BudgetCents: 9, AllowExternal: false}
	legacyJSON, err := json.Marshal(primary)
	if err != nil || strings.Contains(string(legacyJSON), "embedding_") {
		t.Fatal("empty target changed legacy serialized policy", err)
	}
	legacy, err := primary.ForEmbedding()
	if err != nil || legacy != primary {
		t.Fatal("dedicated legacy profile changed", err)
	}
	published := primary
	published.EmbeddingModelVersionID = "embedding-v1"
	published.EmbeddingProvider = "vector-provider"
	published.EmbeddingModel = "vector"
	selected, err := published.ForEmbedding()
	if err != nil || selected.ModelVersionID != "embedding-v1" || selected.Provider != "vector-provider" || selected.Model != "vector" || selected.AllowExternal || selected.BudgetCents != primary.BudgetCents || selected.MaxTokens != primary.MaxTokens || published.Model != "chat" {
		t.Fatal("selection changed shared limits or primary target", err)
	}
	raw, _ := json.Marshal(published)
	if validateAssetContent(AssetModel, raw) != nil {
		t.Fatal("complete embedding target cannot be published")
	}
	for _, invalid := range []ModelPolicy{
		{EmbeddingModelVersionID: "embedding-v1"},
		{EmbeddingProvider: "vector-provider", EmbeddingModel: "vector"},
		{EmbeddingModelVersionID: "embedding-v1", EmbeddingProvider: " ", EmbeddingModel: "vector"},
		{EmbeddingModelVersionID: "embedding-v1 ", EmbeddingProvider: "vector-provider", EmbeddingModel: "vector"},
	} {
		invalid.Provider, invalid.Model, invalid.MaxTokens = "chat-provider", "chat", 512
		if _, err := invalid.ForEmbedding(); err == nil {
			t.Fatal("partial or noncanonical target selected")
		}
		raw, _ := json.Marshal(invalid)
		if validateAssetContent(AssetModel, raw) == nil {
			t.Fatal("invalid embedding target published")
		}
	}
}
