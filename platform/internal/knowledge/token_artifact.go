package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Token artifacts are generated with an actual pinned tokenizer outside the
// platform process. Canonical source facts, ACL, CAS, Outbox and publication
// remain platform-owned. Declared counts are checked against governed model
// usage before a token-artifact index batch can be checkpointed.
const TokenArtifactUnit = "pretokenized-document/v1"

func (c IndexConfig) validChunking() bool {
	switch c.ChunkingUnit {
	case "", "runes":
		return c.WindowRunes > 0 && c.WindowRunes <= 8192 && c.OverlapRunes >= 0 && c.OverlapRunes < c.WindowRunes &&
			c.TokenizerID == "" && c.TokenizerRevision == "" && c.TokenLimit == 0
	case TokenArtifactUnit:
		return c.WindowRunes == 0 && c.OverlapRunes == 0 &&
			strings.TrimSpace(c.TokenizerID) == c.TokenizerID && c.TokenizerID != "" && len(c.TokenizerID) <= 256 &&
			strings.TrimSpace(c.TokenizerRevision) == c.TokenizerRevision && c.TokenizerRevision != "" && len(c.TokenizerRevision) <= 128 &&
			c.TokenLimit > 0 && c.TokenLimit <= 131072
	default:
		return false
	}
}

func tokenArtifactCount(document SourceDocument, config IndexConfig) (int64, error) {
	m := document.Metadata
	if m["chunking_unit"] != TokenArtifactUnit || m["tokenizer_id"] != config.TokenizerID ||
		m["tokenizer_revision"] != config.TokenizerRevision || m["embedding_model_version"] != config.EmbeddingModelVersion {
		return 0, ErrSourceCorrupt
	}
	count, err := strconv.ParseInt(m["full_input_tokens"], 10, 64)
	if err != nil || count < 1 || count > int64(config.TokenLimit) {
		return 0, ErrCorpusLimit
	}
	start, err := strconv.Atoi(m["source_start"])
	if err != nil || start < 0 {
		return 0, ErrSourceCorrupt
	}
	end, err := strconv.Atoi(m["source_end"])
	if err != nil || end <= start || end-start != utf8.RuneCountInString(document.Body) {
		return 0, ErrSourceCorrupt
	}
	digest := sha256.Sum256([]byte(document.Body))
	if m["chunk_body_sha256"] != hex.EncodeToString(digest[:]) {
		return 0, ErrSourceCorrupt
	}
	raw, err := hex.DecodeString(m["raw_document_sha256"])
	if err != nil || len(raw) != 32 || m["raw_document_id"] == "" || m["raw_document_version"] == "" {
		return 0, ErrSourceCorrupt
	}
	return count, nil
}

func tokenArtifactChunk(document SourceDocument, config IndexConfig, configHash string) ([]ProjectedChunk, error) {
	if _, err := tokenArtifactCount(document, config); err != nil {
		return nil, err
	}
	id, err := sourceDigest(struct {
		ID      string
		Version int64
		Config  string
		Body    string
	}{document.ID, document.Version, configHash, document.Body})
	if err != nil {
		return nil, err
	}
	return []ProjectedChunk{{Chunk: Chunk{ID: id, DocumentID: document.ID, DocumentVersion: strconv.FormatInt(document.Version, 10), Text: document.Body},
		ACLRevision: strconv.FormatInt(document.ACLRevision, 10)}}, nil
}
