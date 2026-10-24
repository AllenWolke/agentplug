package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContextCachePolicyPublicationAndQualificationBoundary(t *testing.T) {
	p := ModelPolicy{Provider: "provider", Model: "model", MaxTokens: 256}
	legacy, _ := json.Marshal(p)
	if strings.Contains(string(legacy), "context_cache") {
		t.Fatal("legacy policy changed")
	}
	for _, value := range []ContextCachePolicy{
		{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "session"},
		{Version: "unknown", Mode: "provider_prefix", Isolation: "session"},
		{Version: "context-prefix/v1", Mode: "semantic", Isolation: "session"},
		{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "global"},
	} {
		p.ContextCache = &value
		raw, _ := json.Marshal(p)
		err := validateAssetContent(AssetModel, raw)
		valid := value.Version == "context-prefix/v1" && value.Mode == "provider_prefix" && value.Isolation == "session"
		if (err == nil) != valid {
			t.Fatal("cache policy validation mismatch", value, err)
		}
	}
	s := Snapshot{}
	before := RoutingExecutionContextSHA256(s)
	s.Model.ContextCache = &ContextCachePolicy{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "session"}
	if before == RoutingExecutionContextSHA256(s) {
		t.Fatal("routing qualification ignored cache behavior change")
	}
	embedding, err := s.Model.ForEmbedding()
	if err != nil || embedding.ContextCache != nil {
		t.Fatal("chat prefix leaked into embedding")
	}
}
