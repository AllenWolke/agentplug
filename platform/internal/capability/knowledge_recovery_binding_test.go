package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestKnowledgeRecoveryUsesSameReceiptAfterCheckpointJSONRoundTrip(t *testing.T) {
	for _, mode := range []string{"reordered", "changed-query", "changed-policy", "legacy-exact-wire", "revoked-model"} {
		t.Run(mode, func(t *testing.T) {
			policy := governedInvocationResolver()
			policy.snapshot.Hash = strings.Repeat("b", 64)
			module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, policy)
			gateway := &captureModelGateway{}
			module.SetGovernedModelInvocation(modelAccessResolverFunc(func(_ context.Context, _ sharedkernel.Scope, version string) (modelgateway.Selection, error) {
				if mode == "revoked-model" {
					return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
				}
				return modelgateway.Selection{ModelVersionID: version, ProviderID: "provider-id", ProviderKey: policy.snapshot.Model.Provider, ModelID: "model-id", ModelKey: policy.snapshot.Model.Model, TrustZone: modelgovernance.TrustLocal}, nil
			}), gateway)
			// First SDK entry constructs version_id before digest. JSON checkpoint
			// reload sorts those fields, and may also add irrelevant whitespace.
			original := envelope{Context: capabilityContext(), Policy: policy.snapshot,
				Input: json.RawMessage(`{"query":"question","knowledge_scope":"docs","top_k":3,"skill_bindings":{"guide":{"version_id":"guide-v1","digest":"abc"}}}`)}
			stage := map[string]any{"messages": []map[string]string{{"role": "user", "content": "rewrite question"}}, "max_tokens": 256, "temperature": 0, "prompt_template_hash": policy.snapshot.Prompt.TemplateHash}
			fingerprintJSON, err := json.Marshal(stage)
			if err != nil {
				t.Fatal(err)
			}
			key, err := knowledgeModelCommandKey(original, "/internal/model/generate", fingerprintJSON)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "legacy-exact-wire" {
				binding, _ := json.Marshal([]string{capabilityScopeHash(original.Context), original.Policy.Hash, string(original.Input), "/internal/model/generate", string(fingerprintJSON)})
				key = fmt.Sprintf("knowledge-model:%x", sha256.Sum256(binding))
			}
			fingerprint, err := modelCommandFingerprint([]modelgateway.Message{{Role: "user", Content: "rewrite question"}}, 0, 256, policy.snapshot.Prompt.TemplateHash, policy.snapshot.Model, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			store := module.modelStore.(*memoryModelInvocationStore)
			scope := capabilityScopeHash(original.Context)
			if _, _, err := store.Reserve(context.Background(), scope, key, fingerprint, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := store.Complete(context.Background(), scope, key, fingerprint, map[string]any{"text": "original receipt"}, 0); err != nil {
				t.Fatal(err)
			}
			resumed := original
			if mode != "legacy-exact-wire" {
				resumed.Input = json.RawMessage(`{ "skill_bindings":{"guide":{"digest":"abc","version_id":"guide-v1"}}, "top_k":3, "knowledge_scope":"docs", "query":"question" }`)
			}
			if mode == "changed-query" {
				resumed.Input = json.RawMessage(strings.Replace(string(resumed.Input), `"question"`, `"different question"`, 1))
			}
			if mode == "changed-policy" {
				resumed.Policy.Hash = strings.Repeat("c", 64)
			}
			request := httptest.NewRequest("POST", "/internal/knowledge/answer/recovery", nil)
			request = request.WithContext(context.WithValue(request.Context(), knowledgeRecoveryOnlyKey{}, true))
			result, err := module.knowledgeModelCall(request, resumed, request.Context())(request.Context(), "generate", map[string]any{"messages": stage["messages"], "temperature": 0, "max_tokens": 256})
			if mode == "changed-query" || mode == "changed-policy" || mode == "revoked-model" {
				var modelError *KnowledgeModelError
				if !errors.As(err, &modelError) || result != nil {
					t.Fatalf("changed or revoked recovery disclosed a receipt: %v", err)
				}
				wantStatus := 409
				if mode == "revoked-model" {
					wantStatus = 403
				}
				if modelError.Status != wantStatus {
					t.Fatalf("recovery status=%d want=%d", modelError.Status, wantStatus)
				}
			} else if err != nil || result["text"] != "original receipt" {
				t.Fatalf("same command failed to recover original receipt: %v", err)
			}
			if gateway.calls != 0 || len(store.records) != 1 || store.spent[scope] != 0 {
				t.Fatal("read-only recovery sent a model request or changed the ledger")
			}
		})
	}
}
