package main

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestIndexEmbeddingsUsePublishedGovernedBatchCallback(t *testing.T) {
	for _, mode := range []string{"allowed", "foreign-scope", "different-model", "wrong-receipt", "partial-batch"} {
		t.Run(mode, func(t *testing.T) {
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentID: "agent", AgentInstanceID: "i", InstallationID: "i", AgentVersionID: "v", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
			policy := policyasset.Snapshot{Model: policyasset.ModelPolicy{ModelVersionID: "chat-v1", Provider: "chat", Model: "chat", EmbeddingModelVersionID: "embedding-v1", EmbeddingProvider: "vectors", EmbeddingModel: "vectors"}}
			calls := 0
			m := knowledgeIndexEmbeddings{scope: scope, request: capability.KnowledgeSearchRequest{Policy: policy, ModelCall: func(_ context.Context, operation string, input map[string]any) (map[string]any, error) {
				calls++
				texts, ok := input["texts"].([]string)
				if operation != "embed" || !ok || len(texts) != 2 || texts[0] != "first document" || texts[1] != "second document" {
					t.Fatal("index bypassed governed batch contract")
				}
				version := "embedding-v1"
				if mode == "wrong-receipt" {
					version = "chat-v1"
				}
				vectors := [][]float32{{1, .5}, {.5, 1}}
				if mode == "partial-batch" {
					vectors = vectors[:1]
				}
				return map[string]any{"model_version_id": version, "invocation_id": "scoped-ledger-receipt", "vectors": vectors}, nil
			}}}
			current := scope
			version := "embedding-v1"
			if mode == "foreign-scope" {
				current.PrincipalID = "other"
			}
			if mode == "different-model" {
				version = "other"
			}
			result, err := m.EmbedIndexChunks(context.Background(), current, version, []knowledge.Chunk{{ID: "first", Text: "first document"}, {ID: "second", Text: "second document"}})
			if mode == "allowed" {
				if err != nil || len(result.Vectors) != 2 || result.Vectors["first"][0] != 1 || result.Receipt.ModelVersionID != "embedding-v1" {
					t.Fatal(result, err)
				}
			} else if err == nil || len(result.Vectors) != 0 {
				t.Fatal("invalid index model result admitted", err)
			}
			if (mode == "foreign-scope" || mode == "different-model") && calls != 0 {
				t.Fatal("scope or model mismatch reached callback")
			}
		})
	}
}
