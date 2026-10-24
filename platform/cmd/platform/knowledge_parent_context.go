package main

import (
	"context"
	"strconv"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/knowledge"
)

// Parent expansion reads only the already-published, currently-authorized
// document set. The last capability filter checks each sibling again.
func enrichAuthorizedParentContext(ctx context.Context, authority sourceKnowledgeAuthority, projection knowledge.ProjectionScope, references []map[string]any) error {
	needed := false
	for _, reference := range references {
		if reference["parent_id"] != "" && reference["parent_id"] != nil {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	facts, err := authority.ResolveCurrentDocuments(ctx, authority.scope, authority.knowledgeID)
	if err != nil {
		return err
	}
	if len(facts) > 1000 {
		for _, reference := range references {
			reference["parent_context_status"] = "bounded_scope_lookup_unavailable"
		}
		return nil
	}
	allowed, err := knowledgeFacts(facts)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(facts))
	for _, fact := range facts {
		ids = append(ids, fact.ID)
	}
	snapshot, err := authority.source.SnapshotDocuments(ctx, projection, ids)
	if err != nil {
		return err
	}
	documents := map[string]knowledge.SourceDocument{}
	for _, document := range snapshot.Documents {
		fact, ok := allowed[document.ID]
		if !ok || document.Deleted || document.Fact() != fact {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		documents[document.ID] = document
	}
	for _, reference := range references {
		id, _ := reference["provider_document_id"].(string)
		document, ok := documents[id]
		if !ok {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
		if document.Metadata["parent_scope"] == "block_of_oversized_section" {
			reference["parent_context_status"] = "section_exceeds_context_limit"
			continue
		}
		parent, complete, err := knowledge.AssembleAuthorizedParent(document, snapshot.Documents)
		if err != nil {
			return err
		}
		if !complete {
			reference["parent_context_status"] = "incomplete_authorized_siblings"
			continue
		}
		proof := make([]map[string]any, 0, len(parent.Documents))
		for _, sibling := range parent.Documents {
			proof = append(proof, map[string]any{"source": "platform-knowledge", "provider_knowledge_base_id": projection.KnowledgeID,
				"provider_document_id": sibling.ID, "document_version": strconv.FormatInt(sibling.Version, 10)})
		}
		reference["parent_context"] = map[string]any{"schema_version": "authorized-parent-context/v1",
			"content": parent.Content, "source_span": []int{parent.Start, parent.End}, "source_documents": proof}
		reference["parent_context_status"] = "complete"
	}
	current, err := authority.ResolveCurrentDocuments(ctx, authority.scope, authority.knowledgeID)
	if err != nil {
		return err
	}
	after, err := knowledgeFacts(current)
	if err != nil {
		return err
	}
	for _, document := range snapshot.Documents {
		if after[document.ID] != document.Fact() {
			return knowledge.ErrKnowledgeAuthorityChanged
		}
	}
	return nil
}

func knowledgeFacts(facts []knowledge.DocumentFact) (map[string]knowledge.DocumentFact, error) {
	result := map[string]knowledge.DocumentFact{}
	for _, fact := range facts {
		if fact.ID == "" || result[fact.ID].ID != "" {
			return nil, knowledge.ErrSourceCorrupt
		}
		result[fact.ID] = fact
	}
	return result, nil
}

// Answer generation consumes the same authorized evidence expansion returned
// to Agents. An incomplete source section cannot silently become a fact.
func knowledgeAnswerChunks(chunks []knowledge.HybridChunk, references []map[string]any) ([]knowledge.HybridChunk, error) {
	byID := make(map[string]map[string]any, len(references))
	for _, ref := range references {
		id, ok := ref["clause_or_chunk_id"].(string)
		if !ok || id == "" || byID[id] != nil {
			return nil, knowledge.ErrInvalidQueryStage
		}
		byID[id] = ref
	}
	result := append([]knowledge.HybridChunk(nil), chunks...)
	for index, chunk := range result {
		ref := byID[chunk.ID]
		if ref == nil {
			return nil, knowledge.ErrInvalidQueryStage
		}
		if ref["parent_id"] == nil || ref["parent_id"] == "" {
			continue
		}
		parent, ok := ref["parent_context"].(map[string]any)
		if !ok || ref["parent_context_status"] != "complete" || parent["schema_version"] != "authorized-parent-context/v1" {
			return nil, knowledge.ErrInvalidQueryStage
		}
		text, ok := parent["content"].(string)
		if !ok || text == "" || !utf8.ValidString(text) || utf8.RuneCountInString(text) > 8192 {
			return nil, knowledge.ErrInvalidQueryStage
		}
		result[index].Text = text
	}
	return result, nil
}
