package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func tokenDocumentFixture() (SourceDocument, IndexConfig) {
	body := "监管原文"
	digest := sha256.Sum256([]byte(body))
	config := IndexConfig{EmbeddingModelVersion: "model-v1", Dimensions: 2, MaximumDocuments: 10, MaximumChunks: 10, ChunkingUnit: TokenArtifactUnit, TokenizerID: "actual-tokenizer", TokenizerRevision: "commit-v1", TokenLimit: 512}
	document := SourceDocument{ID: "leaf", Version: 1, ACLRevision: 1, Body: body, Metadata: map[string]string{
		"chunking_unit": TokenArtifactUnit, "tokenizer_id": config.TokenizerID, "tokenizer_revision": config.TokenizerRevision, "embedding_model_version": "model-v1",
		"full_input_tokens": "6", "source_start": "2", "source_end": "6", "chunk_body_sha256": hex.EncodeToString(digest[:]),
		"raw_document_sha256": hex.EncodeToString(digest[:]), "raw_document_id": "raw", "raw_document_version": "1",
	}}
	return document, config
}

func TestTokenArtifactRejectsBodyOffsetCountAndRevisionTampering(t *testing.T) {
	document, config := tokenDocumentFixture()
	if count, err := tokenArtifactCount(document, config); err != nil || count != 6 {
		t.Fatal(count, err)
	}
	for key, value := range map[string]string{"source_end": "7", "chunk_body_sha256": "bad", "tokenizer_revision": "other", "full_input_tokens": "513", "raw_document_sha256": "bad"} {
		changed, _ := tokenDocumentFixture()
		changed.Metadata[key] = value
		if _, err := tokenArtifactCount(changed, config); err == nil {
			t.Fatal("tampered artifact accepted", key)
		}
	}
}

type tokenUsageFixture struct{ usage *int64 }

func (f tokenUsageFixture) EmbedIndexChunks(_ context.Context, _ sharedkernel.Scope, version string, chunks []Chunk) (IndexEmbeddingBatch, error) {
	vectors := map[string][]float32{}
	for _, chunk := range chunks {
		vectors[chunk.ID] = []float32{1, .5}
	}
	return IndexEmbeddingBatch{Vectors: vectors, InputTokens: f.usage, Receipt: QueryStageReceipt{ModelVersionID: version, InvocationID: "governed-receipt"}}, nil
}

func TestTokenArtifactWorkerRequiresExactGovernedUsageBeforeSavingVectors(t *testing.T) {
	for _, value := range []int64{-1, 5, 6, 7} {
		document, config := tokenDocumentFixture()
		owner := cacheFixtureScope()
		scope := ProjectionScope{TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, KnowledgeID: "docs"}
		chunks, err := tokenArtifactChunk(document, config, "config")
		if err != nil {
			t.Fatal(err)
		}
		plan := &IndexPlan{scope: scope, prepared: true, config: config, configHash: "config", sourceDigest: "source", snapshot: SourceSnapshot{Revision: 1, Documents: []SourceDocument{document}}, chunks: chunks}
		var usage *int64
		if value >= 0 {
			usage = &value
		}
		saved := 0
		worker := IndexEmbeddingWorker{Models: tokenUsageFixture{usage}, BatchSize: 16, MaximumBatchBytes: 4096, CheckCurrent: func(context.Context, sharedkernel.Scope, ProjectionScope, string, int64) error { return nil }, SaveCheckpoint: func(_ context.Context, _ sharedkernel.Scope, _ ProjectionScope, raw []byte) (CheckpointReceipt, error) {
			saved++
			_, digest, err := checkpointEnvelope(scope, raw)
			return CheckpointReceipt{RunID: owner.RunID, KnowledgeID: scope.KnowledgeID, Revision: int64(saved), SourceRevision: 1, Digest: digest}, err
		}}
		work, err := worker.Complete(context.Background(), owner, plan)
		if value == 6 {
			if err != nil || work.EmbeddedChunks != 1 || saved != 2 {
				t.Fatal(value, err, saved)
			}
		} else if !errors.Is(err, ErrInvalidQueryStage) || saved != 1 {
			t.Fatal("unverified usage checkpointed", value, err, saved)
		}
	}
}
