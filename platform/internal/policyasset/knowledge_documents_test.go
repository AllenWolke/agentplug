package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestKnowledgeDocumentBindingsAreVersionedControlPlaneFacts(t *testing.T) {
	document := KnowledgeDocumentBinding{KnowledgeScope: "kb", ProviderID: "platform-knowledge", KnowledgeBaseID: "7", ProviderDocumentID: "9007199254740993", OwnerID: "user", OwnershipSource: "reviewed-provider-inventory:42", DocumentVersion: "v1", Status: "active"}
	policy := KnowledgePolicy{AllowedScopes: []string{"kb"}, DocumentBindings: []KnowledgeDocumentBinding{document}}
	if policy.ValidateDocuments() != nil || document.ObjectID() != "platform-knowledge/7/9007199254740993" {
		t.Fatal("valid canonical binding rejected")
	}
	raw, err := json.Marshal(policy)
	if err != nil || validateAssetContent(AssetKnowledge, raw) != nil {
		t.Fatal("knowledge publication rejected document facts", err)
	}
	for _, change := range []func(*KnowledgeDocumentBinding){func(d *KnowledgeDocumentBinding) { d.OwnerID = "" }, func(d *KnowledgeDocumentBinding) { d.OwnershipSource = "" }, func(d *KnowledgeDocumentBinding) { d.KnowledgeScope = "other" }, func(d *KnowledgeDocumentBinding) { d.KnowledgeBaseID = "" }, func(d *KnowledgeDocumentBinding) { d.ProviderDocumentID = "path/fragment" }, func(d *KnowledgeDocumentBinding) { d.ProviderDocumentID = "*" }} {
		invalid := document
		change(&invalid)
		candidate := policy
		candidate.DocumentBindings = []KnowledgeDocumentBinding{invalid}
		body, _ := json.Marshal(candidate)
		if validateAssetContent(AssetKnowledge, body) == nil {
			t.Fatal("untrusted or ambiguous binding accepted", invalid.ObjectID())
		}
	}
	policy.DocumentBindings = append(policy.DocumentBindings, document)
	if policy.ValidateDocuments() == nil {
		t.Fatal("duplicate provenance accepted")
	}
	until := time.Now()
	document.ValidUntil = &until
	if document.Effective(until) {
		t.Fatal("expiry endpoint admitted")
	}
	legacy, _ := json.Marshal(KnowledgePolicy{AllowedScopes: []string{"kb"}})
	if strings.Contains(string(legacy), "document_bindings") {
		t.Fatal("legacy snapshot encoding changed")
	}
}
