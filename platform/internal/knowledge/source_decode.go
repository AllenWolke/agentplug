package knowledge

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/lexagent/platform/internal/jsonvaluecache"
)

// Reuse only pure parsing/integrity validation of exact source-version bytes.
// Every source read still queries current heads in its original transaction,
// compares authoritative columns, and passes the caller/machine ACL fences.
// No document existence, current version, authorization or query is cached.
var sourceDocumentValues = jsonvaluecache.New(512, 8<<20, decodeSourceDocument, func(document SourceDocument) SourceDocument {
	document.Metadata = maps.Clone(document.Metadata)
	document.ACL.Readers = slices.Clone(document.ACL.Readers)
	return document
})

func decodeSourceDocument(raw []byte) (SourceDocument, error) {
	var document SourceDocument
	if json.Unmarshal(raw, &document) != nil {
		return SourceDocument{}, ErrSourceCorrupt
	}
	digest, err := sourceDigest(struct {
		Body     string
		Metadata map[string]string `json:"metadata,omitempty"`
	}{document.Body, document.Metadata})
	if err != nil || digest != document.ContentDigest || document.Version < 1 || document.SourceRevision < 1 || document.ACLRevision < 1 || document.Deleted && document.Body != "" {
		return SourceDocument{}, ErrSourceCorrupt
	}
	return document, nil
}
