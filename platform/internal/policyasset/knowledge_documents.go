package policyasset

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// Published control-plane facts. Never derive ownership from chunk content,
// an Agent's request or a display alias embedded in a retrieved document.
type KnowledgeDocumentBinding struct {
	KnowledgeScope     string     `json:"knowledge_scope"`
	ProviderID         string     `json:"provider_id"`
	KnowledgeBaseID    string     `json:"knowledge_base_id"`
	ProviderDocumentID string     `json:"provider_document_id"`
	OwnerID            string     `json:"owner_id"`
	OwnershipSource    string     `json:"ownership_source"`
	DocumentVersion    string     `json:"document_version"`
	Status             string     `json:"status"`
	ValidFrom          *time.Time `json:"valid_from,omitempty"`
	ValidUntil         *time.Time `json:"valid_until,omitempty"`
}

func (b KnowledgeDocumentBinding) ObjectID() string {
	return b.ProviderID + "/" + b.KnowledgeBaseID + "/" + b.ProviderDocumentID
}
func (b KnowledgeDocumentBinding) Effective(now time.Time) bool {
	return b.Status == "active" && (b.ValidFrom == nil || !now.Before(*b.ValidFrom)) && (b.ValidUntil == nil || now.Before(*b.ValidUntil))
}

func (p KnowledgePolicy) ValidateDocuments() error {
	if len(p.DocumentBindings) > 512 {
		return errors.New("knowledge document bindings exceed limit")
	}
	seen := map[string]bool{}
	for _, b := range p.DocumentBindings {
		for _, id := range []string{b.ProviderID, b.KnowledgeBaseID, b.ProviderDocumentID} {
			if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "/*\x00\r\n") {
				return errors.New("invalid knowledge document identity")
			}
		}
		if !slices.Contains(p.AllowedScopes, b.KnowledgeScope) || b.OwnerID == "" || strings.TrimSpace(b.OwnerID) != b.OwnerID || b.OwnershipSource == "" || len(b.OwnershipSource) > 512 || b.DocumentVersion == "" || len(b.DocumentVersion) > 128 || b.Status != "active" && b.Status != "disabled" && b.Status != "deleted" || b.ValidFrom != nil && b.ValidUntil != nil && !b.ValidUntil.After(*b.ValidFrom) {
			return errors.New("invalid knowledge document binding")
		}
		key := b.KnowledgeScope + "\x00" + b.ObjectID()
		if seen[key] {
			return errors.New("duplicate knowledge document binding")
		}
		seen[key] = true
	}
	return nil
}
