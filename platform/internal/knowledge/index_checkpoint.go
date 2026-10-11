package knowledge

import (
	"context"
	"encoding/json"
)

const IndexCheckpointVersion = "knowledge-index-checkpoint/v1"

// Checkpoints belong to protected platform task storage, not Agent input or
// browser authorization. They contain vectors, config and source references,
// never source document bodies. Task scope/lease/current authority are checked
// by composition before restore or any governed embedding call.
type indexCheckpoint struct {
	Version        string               `json:"version"`
	IntegrityHash  string               `json:"integrity_hash,omitempty"`
	Scope          ProjectionScope      `json:"scope"`
	Config         IndexConfig          `json:"config"`
	SourceRevision int64                `json:"source_revision"`
	SourceDigest   string               `json:"source_digest"`
	ConfigHash     string               `json:"config_hash"`
	ActiveRevision int64                `json:"active_revision"`
	Vectors        map[string][]float32 `json:"vectors"`
}

func (p *IndexPlan) Checkpoint(completed map[string][]float32) ([]byte, error) {
	if p == nil || !p.prepared {
		return nil, ErrInvalidProjection
	}
	vectors := make(map[string][]float32, len(p.chunks))
	accepted := 0
	estimatedBytes := 4096
	for _, chunk := range p.chunks {
		vector := chunk.Embedding
		if len(vector) == 0 {
			if v, ok := completed[chunk.ID]; ok {
				vector = v
				accepted++
			}
		}
		if len(vector) > 0 {
			if _, err := vectorLiteral(vector, p.config.Dimensions); err != nil {
				return nil, err
			}
			estimatedBytes += len(chunk.ID) + 80 + 24*len(vector)
			if estimatedBytes > 64*1024*1024 {
				return nil, ErrCorpusLimit
			}
			vectors[chunk.ID] = append([]float32(nil), vector...)
		}
	}
	if accepted != len(completed) {
		return nil, ErrInvalidProjection
	}
	saved := indexCheckpoint{Version: IndexCheckpointVersion, Scope: p.scope, Config: p.config, SourceRevision: p.snapshot.Revision, SourceDigest: p.sourceDigest, ConfigHash: p.configHash, ActiveRevision: p.activeRevision, Vectors: vectors}
	hash, err := sourceDigest(saved)
	if err != nil {
		return nil, err
	}
	saved.IntegrityHash = hash
	return json.Marshal(saved)
}

// Restore reconstructs source text from committed history and preserves the
// original active-pointer CAS. It rejects obsolete source work early, and never
// treats a historical source snapshot as current permission.
func (c IndexCoordinator) Restore(ctx context.Context, trustedScope ProjectionScope, raw []byte) (*IndexPlan, error) {
	if c.Source.DB == nil || c.Source.DB != c.Projection.DB || !trustedScope.valid() || len(raw) == 0 || len(raw) > 64*1024*1024 {
		return nil, ErrInvalidProjection
	}
	var saved indexCheckpoint
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, ErrInvalidProjection
	}
	integrity := saved.IntegrityHash
	saved.IntegrityHash = ""
	digestHash, err := sourceDigest(saved)
	if err != nil || integrity == "" || digestHash != integrity {
		return nil, ErrSourceCorrupt
	}
	if saved.Version != IndexCheckpointVersion || saved.Scope != trustedScope || !saved.Config.valid() || saved.SourceRevision < 0 || saved.ActiveRevision < 0 {
		return nil, ErrInvalidProjection
	}
	current, err := c.Source.Snapshot(ctx, trustedScope, saved.Config.MaximumDocuments)
	if err != nil {
		return nil, err
	}
	if current.Revision != saved.SourceRevision {
		return nil, ErrSourceConflict
	}
	snapshot, err := c.Source.SnapshotAt(ctx, trustedScope, saved.SourceRevision, saved.Config.MaximumDocuments)
	if err != nil {
		return nil, err
	}
	digest, err := sourceDigest(snapshot)
	if err != nil || digest != saved.SourceDigest {
		return nil, ErrSourceCorrupt
	}
	hash, err := sourceDigest(struct {
		Config             IndexConfig
		Tokenizer, Chunker string
	}{saved.Config, TokenizerVersion, ChunkerVersion})
	if err != nil || hash != saved.ConfigHash {
		return nil, ErrSourceCorrupt
	}
	plan := &IndexPlan{db: c.Projection.DB, scope: trustedScope, config: saved.Config, snapshot: snapshot, configHash: hash, sourceDigest: digest, activeRevision: saved.ActiveRevision}
	count := 0
	for _, document := range snapshot.Documents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunks, err := splitIndexDocument(document, saved.Config, hash)
		if err != nil {
			return nil, err
		}
		for i := range chunks {
			if vector, exists := saved.Vectors[chunks[i].ID]; exists {
				if _, err := vectorLiteral(vector, saved.Config.Dimensions); err != nil {
					return nil, err
				}
				chunks[i].Embedding = append([]float32(nil), vector...)
				count++
			}
		}
		plan.chunks = append(plan.chunks, chunks...)
		if len(plan.chunks) > saved.Config.MaximumChunks {
			return nil, ErrCorpusLimit
		}
	}
	if count != len(saved.Vectors) {
		return nil, ErrSourceCorrupt
	}
	plan.prepared = true
	return plan, nil
}
