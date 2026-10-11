package knowledge

import (
	"strconv"
	"unicode/utf8"
)

// ParentContext contains only source fragments already authorized for the
// caller AND workload. Missing siblings produce no partial parent text.
type ParentContext struct {
	Content    string
	Start, End int
	Documents  []SourceDocument
}

func AssembleAuthorizedParent(child SourceDocument, authorized []SourceDocument) (ParentContext, bool, error) {
	empty := ParentContext{}
	m := child.Metadata
	if m["chunking_unit"] != TokenArtifactUnit || m["parent_id"] == "" {
		return empty, false, nil
	}
	start, e1 := strconv.Atoi(m["parent_start"])
	end, e2 := strconv.Atoi(m["parent_end"])
	if e1 != nil || e2 != nil || start < 0 || end <= start || end-start > 8192 {
		return empty, false, ErrSourceCorrupt
	}
	body := make([]rune, end-start)
	covered := make([]bool, end-start)
	documents := []SourceDocument{}
	for _, document := range authorized {
		other := document.Metadata
		if document.Deleted || other["chunking_unit"] != TokenArtifactUnit || other["parent_id"] != m["parent_id"] ||
			other["raw_document_id"] != m["raw_document_id"] || other["raw_document_version"] != m["raw_document_version"] ||
			other["raw_document_sha256"] != m["raw_document_sha256"] {
			continue
		}
		if other["parent_start"] != m["parent_start"] || other["parent_end"] != m["parent_end"] ||
			other["embedding_model_version"] != m["embedding_model_version"] || other["tokenizer_revision"] != m["tokenizer_revision"] ||
			other["effective_date"] != m["effective_date"] || other["valid_to"] != m["valid_to"] || other["status"] != m["status"] {
			return empty, false, ErrSourceCorrupt
		}
		left, e1 := strconv.Atoi(other["source_start"])
		right, e2 := strconv.Atoi(other["source_end"])
		if e1 != nil || e2 != nil || left < start || right > end || right-left != utf8.RuneCountInString(document.Body) {
			return empty, false, ErrSourceCorrupt
		}
		for index, char := range []rune(document.Body) {
			position := left - start + index
			if covered[position] && body[position] != char {
				return empty, false, ErrSourceCorrupt
			}
			body[position] = char
			covered[position] = true
		}
		documents = append(documents, document)
	}
	for _, present := range covered {
		if !present {
			return empty, false, nil
		}
	}
	return ParentContext{Content: string(body), Start: start, End: end, Documents: documents}, true, nil
}
