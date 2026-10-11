package main

import (
	"github.com/lexagent/platform/internal/knowledge"
	"testing"
)

func TestKnowledgeAnswerUsesCompleteParentWithoutChangingRetrieval(t *testing.T) {
	chunks := []knowledge.HybridChunk{{Chunk: knowledge.Chunk{ID: "child", Text: "threshold"}}}
	refs := []map[string]any{{"clause_or_chunk_id": "child", "parent_id": "parent", "parent_context_status": "complete",
		"parent_context": map[string]any{"schema_version": "authorized-parent-context/v1", "content": "threshold and exception"}}}
	got, err := knowledgeAnswerChunks(chunks, refs)
	if err != nil || got[0].Text != "threshold and exception" || chunks[0].Text != "threshold" {
		t.Fatalf("parent evidence was not preserved: %v", err)
	}
	refs[0]["parent_context_status"] = "incomplete_authorized_siblings"
	if _, err = knowledgeAnswerChunks(chunks, refs); err == nil {
		t.Fatal("incomplete authorized clause must not support an answer")
	}
}
