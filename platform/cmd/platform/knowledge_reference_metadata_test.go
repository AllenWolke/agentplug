package main

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/knowledge"
)

// Stable section identity lets consumers compare the same clause across
// document versions. It must come from the attested source, never a vector's
// unchecked metadata or a different current document version.
func TestReferenceEnrichmentBindsStableSectionToExactSourceVersion(t *testing.T) {
	for _, mode := range []string{"attested", "version-changed", "body-changed", "deleted"} {
		t.Run(mode, func(t *testing.T) {
			doc := knowledge.SourceDocument{ID: "policy-v2", Version: 2, Body: "Ratio is 3%.", Metadata: map[string]string{"section_id": "clause-ratio", "topic_id": "policy", "private_secret": "not-for-reference"}}
			if mode == "version-changed" {
				doc.Version = 3
			}
			if mode == "body-changed" {
				doc.Body = "Different evidence."
			}
			if mode == "deleted" {
				doc.Deleted = true
			}
			source := selectedSourceFixture(func(_ context.Context, _ knowledge.ProjectionScope, ids []string) (knowledge.SourceSnapshot, error) {
				if len(ids) != 1 || ids[0] != doc.ID {
					t.Fatal("unexpected document selection")
				}
				return knowledge.SourceSnapshot{Revision: 2, Documents: []knowledge.SourceDocument{doc}}, nil
			})
			ref := map[string]any{"provider_document_id": "policy-v2", "document_version": "2", "content": "Ratio is 3%."}
			err := enrichKnowledgeReferences(context.Background(), source, knowledge.ProjectionScope{}, []map[string]any{ref})
			if mode == "attested" {
				if err != nil || ref["section_id"] != "clause-ratio" || ref["topic_id"] != "policy" {
					t.Fatal("attested section missing", err)
				}
			} else if err == nil || ref["section_id"] != nil {
				t.Fatal("unattested section admitted", err)
			}
			if _, exists := ref["private_secret"]; exists {
				t.Fatal("private source metadata disclosed")
			}
		})
	}
}
