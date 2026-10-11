package knowledge

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var ProjectionSchema string

var (
	ErrInvalidProjection  = errors.New("invalid knowledge projection")
	ErrProjectionConflict = errors.New("knowledge projection version conflict")
	ErrCorpusLimit        = errors.New("authorized lexical corpus exceeds configured bound")
)

type ProjectionScope struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
	KnowledgeID   string
}

func (s ProjectionScope) valid() bool {
	for _, id := range []string{s.TenantID, s.DepartmentID, s.ApplicationID, s.KnowledgeID} {
		if id == "" || len(id) > 256 {
			return false
		}
	}
	return true
}
func (s ProjectionScope) args() []any {
	return []any{s.TenantID, s.DepartmentID, s.ApplicationID, s.KnowledgeID}
}

type Generation struct {
	ID                    string
	EmbeddingModelVersion string
	Dimensions            int
}

type ProjectedChunk struct {
	Chunk
	ACLRevision string
	Embedding   []float32
}

// DocumentFact must be supplied by current authoritative document and IAM
// checks (both caller and workload), never parsed from request allowlists.
type DocumentFact struct {
	ID          string `json:"document_id"`
	Version     string `json:"document_version"`
	ACLRevision string `json:"acl_revision"`
}

type PostgresProjection struct{ DB *sql.DB }

func vectorLiteral(vector []float32, dimensions int) (string, error) {
	if dimensions < 1 || dimensions > 4096 || len(vector) != dimensions {
		return "", ErrInvalidProjection
	}
	var b strings.Builder
	b.WriteByte('[')
	norm := 0.0
	for index, value := range vector {
		v := float64(value)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", ErrInvalidProjection
		}
		norm += v * v
		if index > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 32))
	}
	if norm == 0 {
		return "", ErrInvalidProjection
	}
	b.WriteByte(']')
	return b.String(), nil
}

// BuildGeneration atomically writes an immutable shadow projection. Ready is
// only a projection receipt: source snapshot completeness must be validated by
// the indexing coordinator before Publish. Failed builds cannot become active.
func (p PostgresProjection) BuildGeneration(ctx context.Context, scope ProjectionScope, generation Generation, chunks []ProjectedChunk) error {
	if p.DB == nil || !scope.valid() || generation.ID == "" || generation.EmbeddingModelVersion == "" || generation.Dimensions < 1 || generation.Dimensions > 4096 {
		return ErrInvalidProjection
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := writeGeneration(ctx, tx, scope, generation, chunks); err != nil {
		return err
	}
	return tx.Commit()
}

func writeGeneration(ctx context.Context, tx *sql.Tx, scope ProjectionScope, generation Generation, chunks []ProjectedChunk) error {
	args := append(scope.args(), generation.ID, generation.EmbeddingModelVersion, generation.Dimensions, TokenizerVersion)
	if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge.generations VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'building')`, args...); err != nil {
		return err
	}
	return writeGenerationChunks(ctx, tx, scope, generation, chunks)
}

func writeGenerationChunks(ctx context.Context, tx *sql.Tx, scope ProjectionScope, generation Generation, chunks []ProjectedChunk) error {
	for _, chunk := range chunks {
		if chunk.ID == "" || chunk.DocumentID == "" || chunk.DocumentVersion == "" || chunk.ACLRevision == "" {
			return ErrInvalidProjection
		}
		if _, err := LexicalTokens(chunk.Text); err != nil {
			return err
		}
		vector, err := vectorLiteral(chunk.Embedding, generation.Dimensions)
		if err != nil {
			return err
		}
		args := append(scope.args(), generation.ID, chunk.DocumentID, chunk.DocumentVersion, chunk.ACLRevision, chunk.ID, chunk.Text, generation.Dimensions, vector)
		if _, err := tx.ExecContext(ctx, `INSERT INTO knowledge.chunks VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::vector)`, args...); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE knowledge.generations SET state='ready' WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND generation_id=$5`, append(scope.args(), generation.ID)...); err != nil {
		return err
	}
	return nil
}

// Publish uses a monotonically increasing CAS revision, so an old publication
// request cannot succeed after switching away and back to the same generation.
func (p PostgresProjection) Publish(ctx context.Context, scope ProjectionScope, generationID string, expectedRevision int64) (int64, error) {
	if p.DB == nil || !scope.valid() || generationID == "" || expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return 0, ErrInvalidProjection
	}
	args := append(scope.args(), generationID, expectedRevision)
	var revision int64
	err := p.DB.QueryRowContext(ctx, `INSERT INTO knowledge.active_generations AS a
 (tenant_id,department_id,application_id,knowledge_id,generation_id,revision)
 SELECT $1,$2,$3,$4,$5,$6::bigint+1 FROM knowledge.generations g
 WHERE g.tenant_id=$1 AND g.department_id=$2 AND g.application_id=$3 AND g.knowledge_id=$4 AND g.generation_id=$5 AND g.state='ready'
 AND NOT EXISTS (SELECT 1 FROM knowledge.index_receipts r WHERE r.tenant_id=g.tenant_id AND r.department_id=g.department_id AND r.application_id=g.application_id AND r.knowledge_id=g.knowledge_id AND r.generation_id=g.generation_id)
 AND (($6::bigint=0 AND NOT EXISTS (SELECT 1 FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4))
 OR EXISTS (SELECT 1 FROM knowledge.active_generations WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND revision=$6::bigint))
 ON CONFLICT (tenant_id,department_id,application_id,knowledge_id)
 DO UPDATE SET generation_id=EXCLUDED.generation_id,revision=EXCLUDED.revision WHERE a.revision=$6::bigint
 RETURNING revision`, args...).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrProjectionConflict
	}
	return revision, err
}

type ProjectionResult struct {
	Generation Generation
	Revision   int64
	Chunks     []HybridChunk
	CacheHit   bool
}

const visibleChunksSQL = `WITH allowed AS (
 SELECT * FROM jsonb_to_recordset($6::jsonb) AS f(document_id text,document_version text,acl_revision text)
), visible AS MATERIALIZED (
 SELECT c.* FROM knowledge.chunks c JOIN allowed f ON c.document_id=f.document_id
 AND c.document_version=f.document_version AND c.acl_revision=f.acl_revision
 WHERE c.tenant_id=$1 AND c.department_id=$2 AND c.application_id=$3 AND c.knowledge_id=$4 AND c.generation_id=$5
) `

// Search uses exact pgvector cosine retrieval. Metadata/source/ACL filtering
// happens BEFORE LIMIT. Both branches capture the same generation in one
// repeatable-read transaction. This is a low-level projection port, NOT an
// HTTP capability: the service must resolve live authority and revalidate
// content before returning it. No estimates masquerade as model embeddings.
func (p PostgresProjection) Search(ctx context.Context, scope ProjectionScope, facts []DocumentFact, modelVersion string, query string, embedding []float32, topK, maximumCorpus int) (ProjectionResult, error) {
	result := ProjectionResult{}
	if p.DB == nil || !scope.valid() || modelVersion == "" || topK < 1 || topK > 100 || maximumCorpus < 1 || maximumCorpus > 100000 {
		return result, ErrInvalidProjection
	}
	versions := make(map[string]string, len(facts))
	for _, fact := range facts {
		if fact.ID == "" || fact.Version == "" || fact.ACLRevision == "" || versions[fact.ID] != "" {
			return result, ErrInvalidProjection
		}
		versions[fact.ID] = fact.Version
	}
	if len(facts) == 0 {
		return result, nil
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		return result, err
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT g.generation_id,g.embedding_model_version,g.dimensions,a.revision FROM knowledge.active_generations a JOIN knowledge.generations g USING (tenant_id,department_id,application_id,knowledge_id,generation_id) WHERE a.tenant_id=$1 AND a.department_id=$2 AND a.application_id=$3 AND a.knowledge_id=$4 AND g.state='ready' AND g.tokenizer_version=$5`, append(scope.args(), TokenizerVersion)...).Scan(&result.Generation.ID, &result.Generation.EmbeddingModelVersion, &result.Generation.Dimensions, &result.Revision)
	if err != nil {
		return result, err
	}
	if modelVersion != result.Generation.EmbeddingModelVersion {
		return result, ErrInvalidProjection
	}
	vector, err := vectorLiteral(embedding, result.Generation.Dimensions)
	if err != nil {
		return result, err
	}
	args := append(scope.args(), result.Generation.ID, string(encoded), maximumCorpus+1)
	rows, err := tx.QueryContext(ctx, visibleChunksSQL+`SELECT chunk_id,document_id,document_version,body FROM visible ORDER BY document_id,chunk_id LIMIT $7`, args...)
	if err != nil {
		return result, err
	}
	var corpus []Chunk
	for rows.Next() {
		var chunk Chunk
		if err := rows.Scan(&chunk.ID, &chunk.DocumentID, &chunk.DocumentVersion, &chunk.Text); err != nil {
			rows.Close()
			return result, err
		}
		corpus = append(corpus, chunk)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	// Refuse a truncated BM25 corpus rather than compute biased DF or claim
	// missing authorized chunks were legitimately ranked below the limit.
	if len(corpus) > maximumCorpus {
		return result, ErrCorpusLimit
	}
	lexical, err := RankBM25(ctx, query, corpus, versions, topK, DefaultBM25Config())
	if err != nil {
		return result, err
	}
	args = append(scope.args(), result.Generation.ID, string(encoded), vector, topK)
	rows, err = tx.QueryContext(ctx, visibleChunksSQL+`SELECT chunk_id,document_id,document_version,body,1-(embedding <=> $7::vector) AS score FROM visible WHERE dimensions=vector_dims($7::vector) ORDER BY embedding <=> $7::vector,document_id,chunk_id LIMIT $8`, args...)
	if err != nil {
		return result, err
	}
	var vectors []RankedChunk
	for rows.Next() {
		var chunk RankedChunk
		if err := rows.Scan(&chunk.ID, &chunk.DocumentID, &chunk.DocumentVersion, &chunk.Text, &chunk.Score); err != nil {
			rows.Close()
			return result, err
		}
		vectors = append(vectors, chunk)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	result.Chunks, err = FuseHybrid(ctx, lexical, vectors, versions, topK, DefaultHybridConfig())
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectionResult{}, err
	}
	return result, nil
}
