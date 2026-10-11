package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func indexFixture(t *testing.T) (IndexCoordinator, ProjectionScope, *sql.DB, IndexConfig) {
	t.Helper()
	source, scope, admin := sourceFixture(t)
	if _, err := admin.Exec(`CREATE TABLE IF NOT EXISTS knowledge_index_fixture_audit(tenant_id text,department_id text,application_id text,knowledge_id text,generation_id text,source_revision bigint,index_revision bigint,PRIMARY KEY(tenant_id,department_id,application_id,knowledge_id,index_revision))`); err != nil {
		t.Fatal(err)
	}
	coordinator := IndexCoordinator{Source: source, Projection: PostgresProjection{DB: source.DB}, RecordPublish: func(ctx context.Context, tx *sql.Tx, s ProjectionScope, id string, sourceRevision, indexRevision int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO knowledge_index_fixture_audit VALUES($1,$2,$3,$4,$5,$6,$7)`, append(s.args(), id, sourceRevision, indexRevision)...)
		return err
	}}
	config := IndexConfig{EmbeddingModelVersion: "fixture-embedding-v1", Dimensions: 2, WindowRunes: 8, OverlapRunes: 2, MaximumDocuments: 1000, MaximumChunks: 1000}
	return coordinator, scope, admin, config
}

// Deterministic vectors test projection semantics, not real model quality,
// billing, budget or live IAM. Production supplies governed model results.
func indexFixtureVectors(plan *IndexPlan) map[string][]float32 {
	result := map[string][]float32{}
	for _, chunk := range plan.RequiredChunks() {
		result[chunk.ID] = []float32{1, 0.5}
	}
	return result
}

func TestPostgresIndexFullIncrementalReuseAndDeletion(t *testing.T) {
	c, scope, _, config := indexFixture(t)
	ctx := context.Background()
	a := sourceCommand("a", "a", 0, 0)
	a.Body = "abcdefghijklmno"
	b := sourceCommand("b", "b", 1, 0)
	b.Body = "zyxwvutsrqp"
	if _, err := c.Source.Change(ctx, scope, a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Source.Change(ctx, scope, b); err != nil {
		t.Fatal(err)
	}
	full, err := c.Prepare(ctx, scope, config, false)
	if err != nil || len(full.RequiredChunks()) != 5 || full.ReusedChunks() != 0 || full.SourceRevision() != 2 {
		t.Fatal("complete full plan", err)
	}
	if err := c.Build(ctx, full, "full", indexFixtureVectors(full)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Projection.Publish(ctx, scope, "full", 0); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("raw publication bypassed completeness fence", err)
	}
	if revision, err := c.Publish(ctx, full, "full"); err != nil || revision != 1 {
		t.Fatal(revision, err)
	}
	a.IdempotencyKey = "acl"
	a.ExpectedSourceRevision = 2
	a.ExpectedDocumentVersion = 1
	a.ACL.Readers = []string{"reader-c"}
	if _, err := c.Source.Change(ctx, scope, a); err != nil {
		t.Fatal(err)
	}
	incremental, err := c.Prepare(ctx, scope, config, true)
	if err != nil || len(incremental.RequiredChunks()) != 0 || incremental.ReusedChunks() != 5 {
		t.Fatal("ACL-only update reembedded unchanged text", err)
	}
	if err := c.Build(ctx, incremental, "acl-update", nil); err != nil {
		t.Fatal(err)
	}
	if revision, err := c.Publish(ctx, incremental, "acl-update"); err != nil || revision != 2 {
		t.Fatal(revision, err)
	}
	deletion := SourceChange{DocumentID: "b", ActorPrincipalID: "source-admin", ExpectedSourceRevision: 3, ExpectedDocumentVersion: 1, IdempotencyKey: "delete-b", Deleted: true}
	if _, err := c.Source.Change(ctx, scope, deletion); err != nil {
		t.Fatal(err)
	}
	incremental, err = c.Prepare(ctx, scope, config, true)
	if err != nil || len(incremental.RequiredChunks()) != 0 || incremental.ReusedChunks() != 3 {
		t.Fatal("deleted document remained in plan", err)
	}
	if err := c.Build(ctx, incremental, "delete-update", nil); err != nil {
		t.Fatal(err)
	}
	if revision, err := c.Publish(ctx, incremental, "delete-update"); err != nil || revision != 3 {
		t.Fatal(revision, err)
	}
	snapshot, err := c.Source.Snapshot(ctx, scope, 1000)
	if err != nil {
		t.Fatal(err)
	}
	facts := []DocumentFact{}
	for _, document := range snapshot.Documents {
		if !document.Deleted {
			facts = append(facts, document.Fact())
		}
	}
	result, err := c.Projection.Search(ctx, scope, facts, config.EmbeddingModelVersion, "abcdefgh", []float32{1, 0.5}, 10, 1000)
	if err != nil || len(result.Chunks) != 3 {
		t.Fatal("published incremental retrieval", result, err)
	}
	for _, chunk := range result.Chunks {
		if chunk.DocumentID != "a" || chunk.DocumentVersion != "2" {
			t.Fatal("stale/deleted version returned", chunk)
		}
	}
	// Content changes request only changed body windows, not the other documents.
	a.IdempotencyKey = "content"
	a.ExpectedSourceRevision = 4
	a.ExpectedDocumentVersion = 2
	a.Body = "abcdefghijklmno NEW"
	if _, err := c.Source.Change(ctx, scope, a); err != nil {
		t.Fatal(err)
	}
	incremental, err = c.Prepare(ctx, scope, config, true)
	if err != nil || incremental.ReusedChunks() != 2 || len(incremental.RequiredChunks()) != 1 {
		t.Fatal("changed-window reuse", err, incremental)
	}
}

func TestPostgresIndexCompletenessCancellationAndRollback(t *testing.T) {
	c, scope, admin, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Build(ctx, plan, "missing", nil); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("partial generation admitted", err)
	}
	vectors := indexFixtureVectors(plan)
	vectors["extra"] = []float32{1, 1}
	if err := c.Build(ctx, plan, "extra", vectors); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("extra generation chunk admitted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Build(canceled, plan, "canceled", indexFixtureVectors(plan)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled build", err)
	}
	if _, err := admin.Exec(`CREATE FUNCTION knowledge.index_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.generation_id='faulted' THEN RAISE EXCEPTION 'index receipt failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER index_fixture_fault BEFORE INSERT ON knowledge.index_receipts FOR EACH ROW EXECUTE FUNCTION knowledge.index_fixture_fault()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(`DROP TRIGGER index_fixture_fault ON knowledge.index_receipts; DROP FUNCTION knowledge.index_fixture_fault()`); err != nil {
			t.Error(err)
		}
	}()
	if err := c.Build(ctx, plan, "faulted", indexFixtureVectors(plan)); err == nil {
		t.Fatal("failed completeness receipt committed")
	}
	for _, query := range []string{`SELECT COUNT(*) FROM knowledge.generations WHERE tenant_id=$1`, `SELECT COUNT(*) FROM knowledge.chunks WHERE tenant_id=$1`, `SELECT COUNT(*) FROM knowledge.index_receipts WHERE tenant_id=$1`} {
		var count int
		if err := c.Projection.DB.QueryRow(query, scope.TenantID).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed build left shadow state", count, err)
		}
	}
	if err := c.Build(ctx, plan, "retry", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if err := c.Build(ctx, plan, "corrupt", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`UPDATE knowledge.chunks SET embedding='[0.1,1]'::vector WHERE tenant_id=$1 AND generation_id='corrupt'`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, plan, "corrupt"); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupted vector manifest activated", err)
	}
	if err := c.Build(ctx, plan, "partial", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`DELETE FROM knowledge.chunks WHERE tenant_id=$1 AND generation_id='partial'`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, plan, "partial"); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("incomplete shadow activated", err)
	}
	if _, err := c.Publish(ctx, plan, "retry"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresIndexSourceFenceCASAndAuditRollback(t *testing.T) {
	c, scope, _, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Build(ctx, plan, "one", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	recorder := c.RecordPublish
	fault := errors.New("injected index publish audit failure")
	c.RecordPublish = func(ctx context.Context, tx *sql.Tx, s ProjectionScope, id string, sr, ir int64) error {
		if err := recorder(ctx, tx, s, id, sr, ir); err != nil {
			return err
		}
		return fault
	}
	if _, err := c.Publish(ctx, plan, "one"); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	var count int
	if err := c.Projection.DB.QueryRow(`SELECT COUNT(*) FROM knowledge.active_generations WHERE tenant_id=$1`, scope.TenantID).Scan(&count); err != nil || count != 0 {
		t.Fatal("publish audit failure activated generation", err)
	}
	c.RecordPublish = recorder
	if _, err := c.Publish(ctx, plan, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, plan, "one"); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("old index revision replay admitted", err)
	}
	current, err := c.Prepare(ctx, scope, config, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Build(ctx, current, "stale", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "source-changed", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, current, "stale"); !errors.Is(err, ErrSourceConflict) {
		t.Fatal("old source snapshot activated", err)
	}
	var id string
	if err := c.Projection.DB.QueryRow(`SELECT generation_id FROM knowledge.active_generations WHERE tenant_id=$1`, scope.TenantID).Scan(&id); err != nil || id != "one" {
		t.Fatal("failed publication changed active pointer", id, err)
	}
}

func TestPostgresIndexConfigurationScopeAndEventContinuity(t *testing.T) {
	c, scope, admin, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Prepare(ctx, scope, config, true); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("incremental build without baseline admitted", err)
	}
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Build(ctx, plan, "one", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Publish(ctx, plan, "one"); err != nil {
		t.Fatal(err)
	}
	changed := config
	changed.EmbeddingModelVersion = "another-version"
	if _, err := c.Prepare(ctx, scope, changed, true); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("different model reused vectors", err)
	}
	full, err := c.Prepare(ctx, scope, changed, false)
	if err != nil || full.ReusedChunks() != 0 || len(full.RequiredChunks()) == 0 {
		t.Fatal("new model full rebuild", err)
	}
	foreign := scope
	foreign.ApplicationID = "another-app"
	isolated, err := c.Prepare(ctx, foreign, config, false)
	if err != nil || isolated.SourceRevision() != 0 || len(isolated.RequiredChunks()) != 0 {
		t.Fatal("foreign scope reused source chunks", err)
	}
	changed = config
	changed.MaximumChunks = 1
	if _, err := c.Prepare(ctx, scope, changed, false); !errors.Is(err, ErrCorpusLimit) {
		t.Fatal("truncated index build admitted", err)
	}
	if _, err := c.Source.Change(ctx, scope, sourceCommand("b", "b", 1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`DELETE FROM platform_knowledge_source_event WHERE tenant_id=$1 AND source_revision=2`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Prepare(ctx, scope, config, true); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("incremental cursor skipped source gap", err)
	}
}
