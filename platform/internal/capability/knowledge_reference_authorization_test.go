package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type referenceAuthorityFixture struct {
	documentAuthorityFixture
	principalDisabled, workloadDisabled bool
}

type recordingReferenceAuthority struct {
	referenceAuthorityFixture
	checked [][]policyasset.KnowledgeDocumentBinding
}

func (f *recordingReferenceAuthority) FilterKnowledgeDocuments(ctx context.Context, s sharedkernel.Scope, scope string, documents []policyasset.KnowledgeDocumentBinding) (KnowledgeDocumentPlan, error) {
	f.checked = append(f.checked, append([]policyasset.KnowledgeDocumentBinding(nil), documents...))
	return f.documentAuthorityFixture.FilterKnowledgeDocuments(ctx, s, scope, documents)
}

func TestSignedCachedReferenceChecksOnlyPublishedRequestedBindingsAndStillRechecksRevocation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			resolver := governedModelResolver("local", false, 0)
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			for i := 0; i < 205; i++ {
				resolver.snapshot.Knowledge.DocumentBindings = append(resolver.snapshot.Knowledge.DocumentBindings, policyasset.KnowledgeDocumentBinding{KnowledgeScope: "platform-knowledge", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: fmt.Sprint(i), OwnerID: "user-a", OwnershipSource: "reviewed", DocumentVersion: "v1", Status: "active"})
			}
			before := append([]policyasset.KnowledgeDocumentBinding(nil), resolver.snapshot.Knowledge.DocumentBindings...)
			module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			authority := &recordingReferenceAuthority{}
			authority.revoke = revoke
			module.SetLiveExecutionAuthority(authority)
			actor := capabilityContext()
			actor.PlatformContextToken = signedContextToken(t, private, actor, time.Now().Unix()-1, time.Now().Unix()+120)
			ref := map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "42", "document_version": "v1"}
			response := capabilityRequest(t, module, "/internal/knowledge/references/authorize", actor, map[string]any{"version": "knowledge-reference-authorization/v1", "knowledge_scope": "platform-knowledge", "references": []map[string]any{ref, ref}})
			want := http.StatusOK
			if revoke {
				want = http.StatusForbidden
			}
			if response.Code != want {
				t.Fatal(response.Code, response.Body.String())
			}
			if len(authority.checked) != 2 {
				t.Fatal("live checks lost", len(authority.checked))
			}
			for _, checked := range authority.checked {
				if len(checked) != 1 || checked[0].ProviderDocumentID != "42" || checked[0].OwnerID != "user-a" {
					t.Fatal("unrelated or caller-supplied facts checked", checked)
				}
			}
			if !reflect.DeepEqual(before, resolver.snapshot.Knowledge.DocumentBindings) {
				t.Fatal("published policy mutated")
			}
		})
	}
}

func (f *referenceAuthorityFixture) AuthorizeCapability(context.Context, sharedkernel.Scope, string, string, string) error {
	if f.principalDisabled {
		return errors.New("principal disabled")
	}
	return nil
}
func (f *referenceAuthorityFixture) AuthenticateWorkload(context.Context, sharedkernel.Scope, string, string, string) error {
	if f.workloadDisabled {
		return errors.New("workload disabled")
	}
	return nil
}

func TestSignedCachedReferencesRequireCurrentDocumentUserAndWorkloadAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"allowed", "revoked-before-result", "empty-acl", "wrong-version", "mixed-denied", "disabled-principal", "disabled-workload", "wrong-scope", "private-body", "missing-version"} {
		t.Run(mode, func(t *testing.T) {
			providerCalls := 0
			provider := knowledgeProviderFunc(func(context.Context, harnessContext, knowledgeQuery) (map[string]any, error) {
				providerCalls++
				return nil, errors.New("must not retrieve")
			})
			resolver := governedModelResolver("local", false, 0)
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Knowledge.DocumentBindings = []policyasset.KnowledgeDocumentBinding{{KnowledgeScope: "platform-knowledge", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "42", OwnerID: "user-a", OwnershipSource: "independent-reviewed-fixture", DocumentVersion: "v1", Status: "active"}}
			module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", provider, resolver)
			authority := &referenceAuthorityFixture{}
			authority.revoke = mode == "revoked-before-result"
			authority.empty = mode == "empty-acl"
			authority.principalDisabled = mode == "disabled-principal"
			authority.workloadDisabled = mode == "disabled-workload"
			module.SetLiveExecutionAuthority(authority)
			actor := capabilityContext()
			actor.PlatformContextToken = signedContextToken(t, private, actor, time.Now().Unix()-1, time.Now().Unix()+120)
			ref := map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "42", "document_version": "v1"}
			input := map[string]any{"version": "knowledge-reference-authorization/v1", "knowledge_scope": "platform-knowledge", "references": []map[string]any{ref}}
			switch mode {
			case "wrong-version":
				ref["document_version"] = "v2"
			case "mixed-denied":
				input["references"] = []map[string]any{ref, {"source": "platform-knowledge", "provider_knowledge_base_id": "7", "provider_document_id": "denied", "document_version": "v1"}}
			case "wrong-scope":
				input["knowledge_scope"] = "denied-scope"
			case "private-body":
				ref["content"] = "PRIVATE-CACHED-BODY"
			case "missing-version":
				delete(ref, "document_version")
			}
			response := capabilityRequest(t, module, "/internal/knowledge/references/authorize", actor, input)
			body := response.Body.String()
			if mode == "allowed" {
				if response.Code != http.StatusOK || !strings.Contains(body, `"authorized":true`) || !strings.Contains(body, `"model_requests_sent":0`) {
					t.Fatal(response.Code, body)
				}
			} else if response.Code != http.StatusForbidden && response.Code != http.StatusBadRequest {
				t.Fatal("unavailable authority passed", response.Code, body)
			}
			if providerCalls != 0 || strings.Contains(body, "PRIVATE-CACHED-BODY") || strings.Contains(body, "provider_document_id") {
				t.Fatal("retrieval or evidence disclosure occurred", providerCalls, body)
			}
		})
	}
}
