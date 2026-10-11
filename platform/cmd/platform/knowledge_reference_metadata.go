package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/knowledge"
)

// Enrich only references already returned by the governed retriever. A source
// change between retrieval and enrichment fails closed rather than attaching
// new metadata to an older vector/document version.
func enrichKnowledgeReferences(ctx context.Context, source selectedKnowledgeSource, scope knowledge.ProjectionScope, references []map[string]any) error {
	ids, seen := []string{}, map[string]bool{}
	for _, ref := range references {
		id, _ := ref["provider_document_id"].(string)
		if id == "" {
			return knowledge.ErrSourceCorrupt
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	snapshot, err := source.SnapshotDocuments(ctx, scope, ids)
	if err != nil {
		return err
	}
	documents := map[string]knowledge.SourceDocument{}
	for _, document := range snapshot.Documents {
		if !seen[document.ID] || document.Deleted {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		documents[document.ID] = document
	}
	for _, ref := range references {
		id, _ := ref["provider_document_id"].(string)
		document, found := documents[id]
		version, _ := ref["document_version"].(string)
		if !found || strconv.FormatInt(document.Version, 10) != version {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		body, _ := ref["content"].(string)
		if body == "" || !strings.Contains(document.Body, body) {
			return knowledge.ErrSourceCorrupt
		}
		delete(ref, "status") // Do not invent effective status for missing metadata.
		for _, key := range []string{"title", "status", "effective_date", "valid_to", "authority_level", "topic_id", "raw_document_id", "raw_document_version", "raw_document_sha256", "parent_id", "section", "language", "page"} {
			if value := document.Metadata[key]; value != "" {
				ref[key] = value
			}
		}
		for _, key := range []string{"institution_types", "report_types", "supersedes"} {
			if value := document.Metadata[key]; value != "" {
				var items []string
				if json.Unmarshal([]byte(value), &items) != nil {
					return knowledge.ErrSourceCorrupt
				}
				ref[key] = items
			}
		}
		if document.Metadata["chunking_unit"] == knowledge.TokenArtifactUnit {
			start, startErr := strconv.Atoi(document.Metadata["source_start"])
			end, endErr := strconv.Atoi(document.Metadata["source_end"])
			if startErr != nil || endErr != nil || document.Body != body || start < 0 || end-start != utf8.RuneCountInString(body) {
				return knowledge.ErrSourceCorrupt
			}
			ref["source_span"], ref["source_span_unit"] = []int{start, end}, "unicode-codepoint"
		} else if strings.Count(document.Body, body) == 1 {
			start := utf8.RuneCountInString(document.Body[:strings.Index(document.Body, body)])
			ref["source_span"], ref["source_span_unit"] = []int{start, start + utf8.RuneCountInString(body)}, "document-unicode-codepoint"
		} else {
			ref["source_span_status"] = "ambiguous_requires_source_lookup"
		}
	}
	return nil
}
