package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
)

const ChunkerVersion = "unicode-rune-window-v1"

type IndexConfig struct {
	EmbeddingModelVersion string
	Dimensions            int
	WindowRunes           int
	OverlapRunes          int
	MaximumDocuments      int
	MaximumChunks         int
	ChunkingUnit          string `json:"ChunkingUnit,omitempty"`
	TokenizerID           string `json:"TokenizerID,omitempty"`
	TokenizerRevision     string `json:"TokenizerRevision,omitempty"`
	TokenLimit            int    `json:"TokenLimit,omitempty"`
}

func (c IndexConfig) valid() bool {
	return c.EmbeddingModelVersion != "" && len(c.EmbeddingModelVersion) <= 256 && c.Dimensions > 0 && c.Dimensions <= 4096 && c.validChunking() && c.MaximumDocuments > 0 && c.MaximumDocuments <= 100000 && c.MaximumChunks > 0 && c.MaximumChunks <= 100000
}

type IndexPlan struct {
	db             *sql.DB
	scope          ProjectionScope
	config         IndexConfig
	snapshot       SourceSnapshot
	chunks         []ProjectedChunk
	configHash     string
	sourceDigest   string
	activeRevision int64
	prepared       bool
}

// RequiredChunks returns copies; embedding results cannot alter captured source
// facts, boundaries or the completeness plan. Only missing vectors are supplied.
func (p *IndexPlan) RequiredChunks() []Chunk {
	result := []Chunk{}
	if p == nil {
		return result
	}
	for _, chunk := range p.chunks {
		if len(chunk.Embedding) == 0 {
			result = append(result, chunk.Chunk)
		}
	}
	return result
}
func (p *IndexPlan) SourceRevision() int64 {
	if p == nil {
		return 0
	}
	return p.snapshot.Revision
}
func (p *IndexPlan) ReusedChunks() int {
	n := 0
	if p != nil {
		for _, c := range p.chunks {
			if len(c.Embedding) > 0 {
				n++
			}
		}
	}
	return n
}

// IndexCoordinator is a platform-internal port, not an Agent API. Composition
// must validate live index-management authority and provide governed embedding
// results with price/budget/usage/cancellation before Build. Source and projection
// publish in one database transaction; another database cannot pass its source
// head/version checks. No distributed atomicity is assumed.
type IndexCoordinator struct {
	Source       PostgresSource
	Projection   PostgresProjection
	Cancellation *IndexCancellation
	// Acquire composition's IAM fence before any projection/source row locks.
	GuardPublishTx func(context.Context, *sql.Tx, ProjectionScope) error
	RecordPublish  func(context.Context, *sql.Tx, ProjectionScope, string, int64, int64) error
}

func splitIndexDocument(document SourceDocument, config IndexConfig, configHash string) ([]ProjectedChunk, error) {
	result := []ProjectedChunk{}
	if document.Deleted {
		return result, nil
	}
	if config.ChunkingUnit == TokenArtifactUnit {
		return tokenArtifactChunk(document, config, configHash)
	}
	text := []rune(document.Body)
	if len(text) == 0 {
		return nil, ErrSourceCorrupt
	}
	for offset := 0; offset < len(text); offset += config.WindowRunes - config.OverlapRunes {
		end := offset + config.WindowRunes
		if end > len(text) {
			end = len(text)
		}
		body := string(text[offset:end])
		id, err := sourceDigest(struct {
			ID      string
			Version int64
			Config  string
			Offset  int
			Body    string
		}{document.ID, document.Version, configHash, offset, body})
		if err != nil {
			return nil, err
		}
		result = append(result, ProjectedChunk{Chunk: Chunk{ID: id, DocumentID: document.ID, DocumentVersion: strconv.FormatInt(document.Version, 10), Text: body}, ACLRevision: strconv.FormatInt(document.ACLRevision, 10)})
		if end == len(text) {
			break
		}
	}
	return result, nil
}

// Prepare captures a complete source snapshot. Incremental mode consumes the
// contiguous source Outbox and reuses vectors only for the same configuration,
// document and exact chunk body; ACL/content metadata gets the new source version.
// Changing the embedding/chunking configuration requires an explicit full build.
func (c IndexCoordinator) Prepare(ctx context.Context, scope ProjectionScope, config IndexConfig, incremental bool) (*IndexPlan, error) {
	if c.Source.DB == nil || c.Projection.DB == nil || c.Source.DB != c.Projection.DB || !scope.valid() || !config.valid() {
		return nil, ErrInvalidProjection
	}
	snapshot, err := c.Source.Snapshot(ctx, scope, config.MaximumDocuments)
	if err != nil {
		return nil, err
	}
	hash, err := sourceDigest(struct {
		Config             IndexConfig
		Tokenizer, Chunker string
	}{config, TokenizerVersion, ChunkerVersion})
	if err != nil {
		return nil, err
	}
	digest, err := sourceDigest(snapshot)
	if err != nil {
		return nil, err
	}
	plan := &IndexPlan{scope: scope, config: config, snapshot: snapshot, db: c.Projection.DB, configHash: hash, sourceDigest: digest}
	var baseID, baseHash, baseManifest string
	var baseSourceRevision int64
	var baseCount int
	err = c.Projection.DB.QueryRowContext(ctx, `SELECT a.generation_id,a.revision,COALESCE(r.source_revision,-1),COALESCE(r.config_hash,''),COALESCE(r.chunk_count,0),COALESCE(r.manifest_hash,'') FROM knowledge.active_generations a LEFT JOIN knowledge.index_receipts r USING(tenant_id,department_id,application_id,knowledge_id,generation_id) WHERE a.tenant_id=$1 AND a.department_id=$2 AND a.application_id=$3 AND a.knowledge_id=$4`, scope.args()...).Scan(&baseID, &plan.activeRevision, &baseSourceRevision, &baseHash, &baseCount, &baseManifest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if incremental && (errors.Is(err, sql.ErrNoRows) || baseHash != hash || baseSourceRevision < 0 || baseSourceRevision > snapshot.Revision) {
		return nil, ErrProjectionConflict
	}
	reused := map[string][]float32{}
	if incremental {
		// Validate every committed event up to the captured snapshot before reuse.
		cursor := baseSourceRevision
		for cursor < snapshot.Revision {
			page, err := c.Source.EventsAfter(ctx, scope, cursor, 1000)
			if err != nil {
				return nil, err
			}
			if len(page.Events) == 0 {
				return nil, ErrSourceCorrupt
			}
			for _, event := range page.Events {
				if event.SourceRevision > snapshot.Revision {
					break
				}
				cursor = event.SourceRevision
			}
		}
		if baseCount > config.MaximumChunks {
			return nil, ErrCorpusLimit
		}
		rows, err := c.Projection.DB.QueryContext(ctx, `SELECT chunk_id,document_id,document_version,acl_revision,body,embedding::text FROM knowledge.chunks WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5 ORDER BY document_id,chunk_id LIMIT $6`, append(scope.args(), baseID, config.MaximumChunks+1)...)
		if err != nil {
			return nil, err
		}
		count := 0
		baseline := []ProjectedChunk{}
		for rows.Next() {
			var chunk ProjectedChunk
			var raw []byte
			var vector []float32
			if err := rows.Scan(&chunk.ID, &chunk.DocumentID, &chunk.DocumentVersion, &chunk.ACLRevision, &chunk.Text, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			if err := json.Unmarshal(raw, &vector); err != nil {
				rows.Close()
				return nil, ErrSourceCorrupt
			}
			if _, err := vectorLiteral(vector, config.Dimensions); err != nil {
				rows.Close()
				return nil, ErrSourceCorrupt
			}
			chunk.Embedding = vector
			baseline = append(baseline, chunk)
			key, _ := sourceDigest([]string{chunk.DocumentID, chunk.Text})
			reused[key] = vector
			count++
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		computedManifest, err := indexManifestHash(baseline)
		if err != nil || computedManifest != baseManifest {
			return nil, ErrSourceCorrupt
		}
		if count != baseCount {
			return nil, ErrSourceCorrupt
		}
	}
	for _, document := range snapshot.Documents {
		chunks, err := splitIndexDocument(document, config, hash)
		if err != nil {
			return nil, err
		}
		for i := range chunks {
			key, _ := sourceDigest([]string{document.ID, chunks[i].Text})
			chunks[i].Embedding = append([]float32(nil), reused[key]...)
		}
		plan.chunks = append(plan.chunks, chunks...)
		if len(plan.chunks) > config.MaximumChunks {
			return nil, ErrCorpusLimit
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan.prepared = true
	return plan, nil
}

func indexManifestHash(chunks []ProjectedChunk) (string, error) {
	sorted := append([]ProjectedChunk{}, chunks...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].DocumentID != sorted[j].DocumentID {
			return sorted[i].DocumentID < sorted[j].DocumentID
		}
		return sorted[i].ID < sorted[j].ID
	})
	return sourceDigest(sorted)
}

// Build writes a full immutable shadow generation and its completeness receipt
// atomically. Missing/extra/invalid vectors fail before any projection writes.
// Incremental builds copy existing vectors, never mutate the active generation.
func (c IndexCoordinator) Build(ctx context.Context, plan *IndexPlan, generationID string, vectors map[string][]float32) error {
	return c.build(ctx, plan, generationID, vectors, false)
}

// BuildOrReplay supports task recovery with a stable generation ID. A replay
// accepts only the exact source/config/manifest and verified immutable rows.
// A conflicting or raw projection generation is never overwritten.
func (c IndexCoordinator) BuildOrReplay(ctx context.Context, plan *IndexPlan, generationID string, vectors map[string][]float32) error {
	return c.build(ctx, plan, generationID, vectors, true)
}

func (c IndexCoordinator) build(ctx context.Context, plan *IndexPlan, generationID string, vectors map[string][]float32, replay bool) error {
	if c.Projection.DB == nil || plan == nil || !plan.prepared || plan.db != c.Projection.DB || c.Source.DB != c.Projection.DB || generationID == "" || len(generationID) > 256 {
		return ErrInvalidProjection
	}
	chunks := make([]ProjectedChunk, len(plan.chunks))
	needed := 0
	for i, chunk := range plan.chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunks[i] = chunk
		if len(chunk.Embedding) == 0 {
			vector, exists := vectors[chunk.ID]
			if !exists {
				return ErrInvalidProjection
			}
			chunks[i].Embedding = append([]float32(nil), vector...)
			needed++
		}
		if _, err := vectorLiteral(chunks[i].Embedding, plan.config.Dimensions); err != nil {
			return err
		}
	}
	if needed != len(vectors) {
		return ErrInvalidProjection
	}
	manifest, err := indexManifestHash(chunks)
	if err != nil {
		return err
	}
	tx, err := c.Projection.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	generation := Generation{ID: generationID, EmbeddingModelVersion: plan.config.EmbeddingModelVersion, Dimensions: plan.config.Dimensions}
	if replay {
		// The unique insert also serializes simultaneous retries. No placeholder
		// becomes visible: chunks and completeness receipt commit in this TX.
		result, err := tx.ExecContext(ctx, `INSERT INTO knowledge.generations VALUES($1,$2,$3,$4,$5,$6,$7,$8,'building') ON CONFLICT DO NOTHING`, append(plan.scope.args(), generation.ID, generation.EmbeddingModelVersion, generation.Dimensions, TokenizerVersion)...)
		if err != nil {
			return err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if inserted == 0 {
			var storedManifest string
			if err := tx.QueryRowContext(ctx, `SELECT manifest_hash FROM knowledge.index_receipts WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5 FOR SHARE`, append(plan.scope.args(), generationID)...).Scan(&storedManifest); errors.Is(err, sql.ErrNoRows) {
				return ErrProjectionConflict
			} else if err != nil {
				return err
			}
			if storedManifest != manifest {
				return ErrProjectionConflict
			}
			if err := verifyIndexShadow(ctx, tx, plan, generationID); err != nil {
				return err
			}
			return tx.Commit()
		}
		if err := writeGenerationChunks(ctx, tx, plan.scope, generation, chunks); err != nil {
			return err
		}
	} else if err := writeGeneration(ctx, tx, plan.scope, generation, chunks); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge.index_receipts(tenant_id,department_id,application_id,knowledge_id,generation_id,source_revision,config_hash,source_digest,manifest_hash,document_count,chunk_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, append(plan.scope.args(), generationID, plan.snapshot.Revision, plan.configHash, plan.sourceDigest, manifest, len(plan.snapshot.Documents), len(chunks))...); err != nil {
		return err
	}
	return tx.Commit()
}

// Publish holds the source head lock through pointer/audit commit. A changed
// source, stale active revision, missing completeness receipt or audit failure
// cannot activate the shadow. Source-bound generations cannot use raw Publish.
func (c IndexCoordinator) Publish(ctx context.Context, plan *IndexPlan, generationID string) (int64, error) {
	return c.publish(ctx, plan, generationID, false)
}

// PublishOrReplay acknowledges an already committed publication only while
// that exact generation and base+1 revision remain active and source-current.
// It rechecks live authority and shadow integrity; it never reactivates an old
// generation or emits a duplicate publication audit.
func (c IndexCoordinator) PublishOrReplay(ctx context.Context, plan *IndexPlan, generationID string) (int64, error) {
	return c.publish(ctx, plan, generationID, true)
}

func (c IndexCoordinator) publish(ctx context.Context, plan *IndexPlan, generationID string, replay bool) (int64, error) {
	if c.Projection.DB == nil || plan == nil || !plan.prepared || plan.db != c.Projection.DB || c.Source.DB != c.Projection.DB || generationID == "" || plan.activeRevision == math.MaxInt64 {
		return 0, ErrInvalidProjection
	}
	if c.RecordPublish == nil {
		return 0, ErrSourceRecorderUnavailable
	}
	tx, err := c.Projection.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if c.GuardPublishTx != nil {
		if err := c.GuardPublishTx(ctx, tx, plan.scope); err != nil {
			return 0, err
		}
	}
	if err := verifyIndexShadow(ctx, tx, plan, generationID); err != nil {
		return 0, err
	}
	// Empty collections still need a durable source head for the publication fence.
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_source_head(tenant_id,department_id,application_id,knowledge_id,source_revision) VALUES($1,$2,$3,$4,0) ON CONFLICT DO NOTHING`, plan.scope.args()...); err != nil {
		return 0, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, plan.scope.args()...).Scan(&revision); err != nil {
		return 0, err
	}
	if revision != plan.snapshot.Revision {
		return 0, ErrSourceConflict
	}
	if replay {
		var activeID string
		var activeRevision int64
		err := tx.QueryRowContext(ctx, `SELECT generation_id,revision FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, plan.scope.args()...).Scan(&activeID, &activeRevision)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		if err == nil && activeID == generationID && activeRevision == plan.activeRevision+1 {
			if c.Cancellation != nil {
				if err := c.Cancellation.checkReplayTx(ctx, tx, plan, generationID); err != nil {
					return 0, err
				}
			}
			// Locks may have waited past natural expiry. Recheck before the
			// acknowledgment even though replay emits no new audit record.
			if c.GuardPublishTx != nil {
				if err := c.GuardPublishTx(ctx, tx, plan.scope); err != nil {
					return 0, err
				}
			}
			if err := tx.Commit(); err != nil {
				return 0, err
			}
			return activeRevision, nil
		}
	}
	stamp := ""
	if c.Cancellation != nil {
		stamp, err = c.Cancellation.prepareTx(ctx, tx, plan, generationID)
		if err != nil {
			return 0, err
		}
	}
	args := append(plan.scope.args(), generationID, plan.activeRevision, plan.snapshot.Revision, plan.configHash, plan.sourceDigest)
	err = tx.QueryRowContext(ctx, `INSERT INTO knowledge.active_generations AS a(tenant_id,department_id,application_id,knowledge_id,generation_id,revision)
 SELECT $1,$2,$3,$4,$5,$6::bigint+1 FROM knowledge.generations g JOIN knowledge.index_receipts r USING(tenant_id,department_id,application_id,knowledge_id,generation_id)
 WHERE g.tenant_id=$1 AND g.department_id=$2 AND g.application_id=$3 AND g.knowledge_id=$4 AND g.generation_id=$5 AND g.state='ready' AND r.source_revision=$7 AND r.config_hash=$8 AND r.source_digest=$9
 AND (($6::bigint=0 AND NOT EXISTS(SELECT 1 FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4)) OR EXISTS(SELECT 1 FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND revision=$6))
 ON CONFLICT(tenant_id,department_id,application_id,knowledge_id) DO UPDATE SET generation_id=EXCLUDED.generation_id,revision=EXCLUDED.revision WHERE a.revision=$6 RETURNING revision`, args...).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrProjectionConflict
	}
	if err != nil {
		return 0, err
	}
	if c.Cancellation != nil {
		changed, err := tx.ExecContext(ctx, `UPDATE knowledge.active_generations SET effect_stamp=$5 WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$6 AND revision=$7`, append(plan.scope.args(), stamp, generationID, revision)...)
		if err != nil {
			return 0, err
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return 0, ErrProjectionConflict
		}
	}
	if err := c.RecordPublish(ctx, tx, plan.scope, generationID, plan.snapshot.Revision, revision); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revision, nil
}

func verifyIndexShadow(ctx context.Context, tx *sql.Tx, plan *IndexPlan, generationID string) error {
	var model, tokenizer, state string
	var dimensions int
	err := tx.QueryRowContext(ctx, `SELECT embedding_model_version,dimensions,tokenizer_version,state FROM knowledge.generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5 FOR SHARE`, append(plan.scope.args(), generationID)...).Scan(&model, &dimensions, &tokenizer, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProjectionConflict
	}
	if err != nil {
		return err
	}
	if model != plan.config.EmbeddingModelVersion || dimensions != plan.config.Dimensions || tokenizer != TokenizerVersion || state != "ready" {
		return ErrProjectionConflict
	}
	var manifest string
	var count int
	err = tx.QueryRowContext(ctx, `SELECT manifest_hash,chunk_count FROM knowledge.index_receipts WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5 AND source_revision=$6 AND config_hash=$7 AND source_digest=$8 AND document_count=$9 FOR SHARE`, append(plan.scope.args(), generationID, plan.snapshot.Revision, plan.configHash, plan.sourceDigest, len(plan.snapshot.Documents))...).Scan(&manifest, &count)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProjectionConflict
	}
	if err != nil {
		return err
	}
	if count != len(plan.chunks) || count > plan.config.MaximumChunks {
		return ErrSourceCorrupt
	}
	expected := make(map[string]ProjectedChunk, len(plan.chunks))
	for _, chunk := range plan.chunks {
		expected[chunk.ID] = chunk
	}
	rows, err := tx.QueryContext(ctx, `SELECT chunk_id,document_id,document_version,acl_revision,body,embedding::text FROM knowledge.chunks WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5 ORDER BY document_id,chunk_id LIMIT $6 FOR SHARE`, append(plan.scope.args(), generationID, plan.config.MaximumChunks+1)...)
	if err != nil {
		return err
	}
	chunks := []ProjectedChunk{}
	for rows.Next() {
		var chunk ProjectedChunk
		var raw []byte
		if err := ctx.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Scan(&chunk.ID, &chunk.DocumentID, &chunk.DocumentVersion, &chunk.ACLRevision, &chunk.Text, &raw); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(raw, &chunk.Embedding); err != nil {
			rows.Close()
			return ErrSourceCorrupt
		}
		spec, exists := expected[chunk.ID]
		if !exists || spec.Chunk != chunk.Chunk || spec.ACLRevision != chunk.ACLRevision {
			rows.Close()
			return ErrSourceCorrupt
		}
		if _, err := vectorLiteral(chunk.Embedding, plan.config.Dimensions); err != nil {
			rows.Close()
			return ErrSourceCorrupt
		}
		delete(expected, chunk.ID)
		chunks = append(chunks, chunk)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	hash, err := indexManifestHash(chunks)
	if err != nil || hash != manifest || len(chunks) != count || len(expected) != 0 {
		return ErrSourceCorrupt
	}
	return nil
}
