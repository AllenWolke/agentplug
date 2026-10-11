package knowledge

import (
	"errors"
	"strconv"
	"testing"
)

func parentPart(id, body string, start, end int) SourceDocument {
	return SourceDocument{ID: id, Version: 1, Body: body, Metadata: map[string]string{
		"chunking_unit": TokenArtifactUnit, "parent_id": "p", "parent_start": "0", "parent_end": "6",
		"raw_document_id": "raw", "raw_document_version": "v1", "raw_document_sha256": "rawhash",
		"embedding_model_version": "e1", "tokenizer_revision": "t1", "effective_date": "2026-01-01",
		"status": "effective", "source_start": strconv.Itoa(start), "source_end": strconv.Itoa(end)}}
}

func TestParentRequiresAllAuthorizedFragments(t *testing.T) {
	child := parentPart("c1", "金额1万", 0, 4)
	sibling := parentPart("c2", "例外", 4, 6)
	if _, complete, err := AssembleAuthorizedParent(child, []SourceDocument{child}); err != nil || complete {
		t.Fatal("partial parent released")
	}
	result, complete, err := AssembleAuthorizedParent(child, []SourceDocument{child, sibling})
	if err != nil || !complete || result.Content != "金额1万例外" || len(result.Documents) != 2 {
		t.Fatal(result, complete, err)
	}
}

func TestParentRejectsVersionAndOverlappingConflict(t *testing.T) {
	child := parentPart("c1", "金额1万", 0, 4)
	sibling := parentPart("c2", "例外", 4, 6)
	sibling.Metadata["raw_document_version"] = "v2"
	if _, complete, err := AssembleAuthorizedParent(child, []SourceDocument{child, sibling}); err != nil || complete {
		t.Fatal("different source version merged")
	}
	conflict := parentPart("c3", "亿元", 2, 4)
	if _, _, err := AssembleAuthorizedParent(child, []SourceDocument{child, conflict}); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal(err)
	}
}
