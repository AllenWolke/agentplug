package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func projectionFixture(t *testing.T) (PostgresProjection, ProjectionScope) {
	t.Helper()
	dsn := os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open fixture failed")
	}
	t.Cleanup(func() { db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal("isolated PostgreSQL unavailable")
	}
	scope := ProjectionScope{TenantID: fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano()), DepartmentID: "dept", ApplicationID: "app", KnowledgeID: "docs"}
	return PostgresProjection{DB: db}, scope
}

func TestPostgresMetadataFilteringBeforeVectorLimit(t *testing.T) {
	p, scope := projectionFixture(t)
	ctx := context.Background()
	g := Generation{ID: "g1", EmbeddingModelVersion: "embedding-v1", Dimensions: 2}
	chunks := []ProjectedChunk{
		{Chunk: Chunk{ID: "visible", DocumentID: "visible", DocumentVersion: "v1", Text: "recovery procedure"}, ACLRevision: "acl1", Embedding: []float32{0.8, 0.6}},
		{Chunk: Chunk{ID: "private", DocumentID: "private", DocumentVersion: "v1", Text: "recovery private"}, ACLRevision: "acl1", Embedding: []float32{1, 0}},
		{Chunk: Chunk{ID: "stale", DocumentID: "stale", DocumentVersion: "v0", Text: "recovery obsolete"}, ACLRevision: "acl1", Embedding: []float32{1, 0}},
		{Chunk: Chunk{ID: "revoked", DocumentID: "revoked", DocumentVersion: "v1", Text: "recovery revoked"}, ACLRevision: "acl0", Embedding: []float32{1, 0}},
	}
	if err := p.BuildGeneration(ctx, scope, g, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, scope, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	foreign := scope
	foreign.ApplicationID = "another-app"
	if err := p.BuildGeneration(ctx, foreign, g, []ProjectedChunk{{Chunk: Chunk{ID: "foreign", DocumentID: "visible", DocumentVersion: "v1", Text: "recovery foreign"}, ACLRevision: "acl1", Embedding: []float32{1, 0}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, foreign, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	facts := []DocumentFact{{ID: "visible", Version: "v1", ACLRevision: "acl1"}, {ID: "stale", Version: "v1", ACLRevision: "acl1"}, {ID: "revoked", Version: "v1", ACLRevision: "acl1"}}
	result, err := p.Search(ctx, scope, facts, g.EmbeddingModelVersion, "recovery", []float32{1, 0}, 1, 10)
	if err != nil || len(result.Chunks) != 1 || result.Chunks[0].ID != "visible" || result.Chunks[0].VectorRank != 1 || result.Chunks[0].LexicalRank != 1 || result.Revision != 1 {
		t.Fatalf("metadata before TopK failed: %#v %v", result, err)
	}
	denied, err := p.Search(ctx, scope, nil, g.EmbeddingModelVersion, "recovery", []float32{1, 0}, 1, 10)
	if err != nil || len(denied.Chunks) != 0 {
		t.Fatal("empty authority did not fail closed")
	}
	if _, err := p.Search(ctx, scope, facts, "different-model", "recovery", []float32{1, 0}, 1, 10); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("incompatible embedding model accepted")
	}
}

func TestPostgresGenerationCASAndFailedBuild(t *testing.T) {
	p, scope := projectionFixture(t)
	ctx := context.Background()
	if _, err := p.Publish(ctx, scope, "missing", 7); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("nonzero CAS created absent pointer")
	}
	bad := Generation{ID: "bad", EmbeddingModelVersion: "model", Dimensions: 2}
	if err := p.BuildGeneration(ctx, scope, bad, []ProjectedChunk{{Chunk: Chunk{ID: "one", DocumentID: "one", DocumentVersion: "v1", Text: "text"}, ACLRevision: "acl", Embedding: []float32{0, 0}}}); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("zero vector accepted")
	}
	var count int
	if err := p.DB.QueryRowContext(ctx, `SELECT count(*) FROM knowledge.generations WHERE tenant_id=$1`, scope.TenantID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed shadow build was not rolled back")
	}
	for _, id := range []string{"g1", "g2"} {
		if err := p.BuildGeneration(ctx, scope, Generation{ID: id, EmbeddingModelVersion: "model", Dimensions: 2}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Publish(ctx, scope, "g1", 7); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("invalid initial revision accepted")
	}
	for _, step := range []struct {
		id                 string
		expected, revision int64
	}{{"g1", 0, 1}, {"g2", 1, 2}, {"g1", 2, 3}} {
		if revision, err := p.Publish(ctx, scope, step.id, step.expected); err != nil || revision != step.revision {
			t.Fatalf("CAS publication failed: %d %v", revision, err)
		}
	}
	if _, err := p.Publish(ctx, scope, "g2", 1); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("ABA stale publication accepted")
	}
	if err := p.BuildGeneration(ctx, scope, Generation{ID: "g1", EmbeddingModelVersion: "model", Dimensions: 2}, nil); err == nil {
		t.Fatal("immutable generation overwritten")
	}
}

func TestPostgresCorpusBoundAndCancellation(t *testing.T) {
	p, scope := projectionFixture(t)
	ctx := context.Background()
	g := Generation{ID: "g1", EmbeddingModelVersion: "model", Dimensions: 2}
	var chunks []ProjectedChunk
	for _, id := range []string{"a", "b"} {
		chunks = append(chunks, ProjectedChunk{Chunk: Chunk{ID: id, DocumentID: "doc", DocumentVersion: "v1", Text: "procedure"}, ACLRevision: "acl", Embedding: []float32{1, 1}})
	}
	if err := p.BuildGeneration(ctx, scope, g, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, scope, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	facts := []DocumentFact{{ID: "doc", Version: "v1", ACLRevision: "acl"}}
	if _, err := p.Search(ctx, scope, facts, "model", "procedure", []float32{1, 1}, 1, 1); !errors.Is(err, ErrCorpusLimit) {
		t.Fatal("truncated corpus used for BM25 statistics")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Search(canceled, scope, facts, "model", "procedure", []float32{1, 1}, 1, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SQL query executed: %v", err)
	}
}

func TestPostgresRuntimeCannotRunDDL(t *testing.T) {
	p, _ := projectionFixture(t)
	if _, err := p.DB.ExecContext(context.Background(), `CREATE TABLE knowledge.runtime_must_not_create_table (id integer)`); err == nil {
		t.Fatal("runtime identity has DDL privileges")
	}
}

func TestVectorLiteralRejectsInvalidEmbeddings(t *testing.T) {
	for _, vector := range [][]float32{{0, 0}, {1}, {float32(math.NaN()), 1}, {float32(math.Inf(1)), 1}} {
		if _, err := vectorLiteral(vector, 2); !errors.Is(err, ErrInvalidProjection) {
			t.Fatalf("invalid vector accepted: %v", vector)
		}
	}
}

type changingRetrievalAuthority struct {
	calls int
	facts []DocumentFact
	err   error
}

func (a *changingRetrievalAuthority) ResolveCurrentDocuments(_ context.Context, _ sharedkernel.Scope, _ string) ([]DocumentFact, error) {
	a.calls++
	if a.calls == 1 {
		return a.facts, nil
	}
	return nil, a.err
}

func TestPostgresFinalAuthorityRecheckDoesNotLeakContent(t *testing.T) {
	p, s := projectionFixture(t)
	ctx := context.Background()
	g := Generation{ID: "g1", EmbeddingModelVersion: "model", Dimensions: 2}
	if err := p.BuildGeneration(ctx, s, g, []ProjectedChunk{{Chunk: Chunk{ID: "chunk", DocumentID: "doc", DocumentVersion: "v1", Text: "sensitive recovery"}, ACLRevision: "acl", Embedding: []float32{1, 0}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, s, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentInstanceID: "instance", AgentID: "agent", PrincipalID: "user", PrincipalType: "user", InstallationID: "installation", AgentVersionID: "v1", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
	for _, fault := range []error{nil, ErrKnowledgeAuthorityUnavailable} {
		a := &changingRetrievalAuthority{facts: []DocumentFact{{ID: "doc", Version: "v1", ACLRevision: "acl"}}, err: fault}
		r := GovernedProjectionRetriever{Projection: p, Authority: a, MaximumCorpus: 10}
		result, err := r.Retrieve(ctx, scope, s.KnowledgeID, "model", "recovery", []float32{1, 0}, 1)
		if err == nil || len(result.Chunks) != 0 || a.calls != 2 {
			t.Fatalf("post-query revoke/unavailable authority leaked content: %#v %v", result, err)
		}
	}
}
