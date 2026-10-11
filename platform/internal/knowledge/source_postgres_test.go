package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sourceFixture(t *testing.T) (PostgresSource, ProjectionScope, *sql.DB) {
	t.Helper()
	projection, scope := projectionFixture(t)
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/knowledge_test" {
		t.Fatal("source fixture requires verifier-owned loopback knowledge_test")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if _, err := admin.Exec(`CREATE TABLE IF NOT EXISTS knowledge_source_fixture_audit(tenant_id text,department_id text,application_id text,knowledge_id text,source_revision bigint,receipt jsonb NOT NULL,PRIMARY KEY(tenant_id,department_id,application_id,knowledge_id,source_revision))`); err != nil {
		t.Fatal(err)
	}
	store := PostgresSource{DB: projection.DB, RecordChange: func(ctx context.Context, tx *sql.Tx, scope ProjectionScope, receipt SourceReceipt) error {
		raw, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO knowledge_source_fixture_audit VALUES($1,$2,$3,$4,$5,$6::jsonb)`, append(scope.args(), receipt.SourceRevision, string(raw))...)
		return err
	}}
	return store, scope, admin
}

func sourceCommand(id, key string, revision, version int64) SourceChange {
	return SourceChange{DocumentID: id, ActorPrincipalID: "source-admin", IdempotencyKey: key, ExpectedSourceRevision: revision, ExpectedDocumentVersion: version, Body: "restart service 恢复步骤", Metadata: map[string]string{"category": "operations"}, ACL: DocumentACL{OwnerPrincipalID: "owner", Readers: []string{"reader-b", "reader-a"}}}
}

func requireSourceCount(t *testing.T, db *sql.DB, scope ProjectionScope, table string, want int) {
	t.Helper()
	switch table {
	case "platform_knowledge_source_event", "platform_knowledge_document_version", "platform_knowledge_document_head", "knowledge_source_fixture_audit":
	default:
		t.Fatal("unknown fixture table")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, scope.args()...).Scan(&count); err != nil || count != want {
		t.Fatalf("%s count=%d wanted=%d err=%v", table, count, want, err)
	}
}

func TestPostgresSourceVersionsACLAndTombstones(t *testing.T) {
	p, scope, _ := sourceFixture(t)
	ctx := context.Background()
	command := sourceCommand("document", "create", 0, 0)
	first, err := p.Change(ctx, scope, command)
	if err != nil || first.SourceRevision != 1 || first.DocumentVersion != 1 || first.ACLRevision != 1 {
		t.Fatal(first, err)
	}
	replay := command
	replay.ACL.Readers = []string{"reader-a", "reader-b"}
	if got, err := p.Change(ctx, scope, replay); err != nil || got != first {
		t.Fatal("normalized idempotent replay", got, err)
	}
	replay.Body = "different payload"
	if _, err := p.Change(ctx, scope, replay); !errors.Is(err, ErrSourceConflict) {
		t.Fatal("changed replay accepted", err)
	}
	changed := sourceCommand("document", "update", 1, 1)
	changed.Body = "new recovery procedure"
	second, err := p.Change(ctx, scope, changed)
	if err != nil || second.DocumentVersion != 2 || second.ACLRevision != 1 {
		t.Fatal("content update changed ACL", second, err)
	}
	changed = sourceCommand("document", "acl", 2, 2)
	changed.ACL.Readers = []string{"reader-c"}
	third, err := p.Change(ctx, scope, changed)
	if err != nil || third.ACLRevision != 2 || third.DocumentVersion != 3 {
		t.Fatal("ACL revision", third, err)
	}
	tombstone := SourceChange{DocumentID: "document", ActorPrincipalID: "source-admin", ExpectedSourceRevision: 3, ExpectedDocumentVersion: 3, IdempotencyKey: "delete", Deleted: true}
	fourth, err := p.Change(ctx, scope, tombstone)
	if err != nil || !fourth.Deleted || fourth.DocumentVersion != 4 || fourth.ACLRevision != 2 {
		t.Fatal("tombstone", fourth, err)
	}
	snapshot, err := p.Snapshot(ctx, scope, 10)
	if err != nil || snapshot.Revision != 4 || len(snapshot.Documents) != 1 || !snapshot.Documents[0].Deleted || snapshot.Documents[0].Body != "" {
		t.Fatal("deleted head snapshot", snapshot, err)
	}
	old, err := p.ReadVersion(ctx, scope, "document", 1)
	if err != nil || old.Body != command.Body || old.Deleted || old.Fact().Version != "1" {
		t.Fatal("immutable original version", old, err)
	}
	page, err := p.EventsAfter(ctx, scope, 0, 2)
	if err != nil || page.HeadRevision != 4 || len(page.Events) != 2 || page.Events[0] != first || page.Events[1] != second {
		t.Fatal("event prefix", page, err)
	}
	page, err = p.EventsAfter(ctx, scope, 2, 2)
	if err != nil || len(page.Events) != 2 || page.Events[0] != third || page.Events[1] != fourth {
		t.Fatal("event suffix", page, err)
	}
	revived := sourceCommand("document", "revive", 4, 4)
	fifth, err := p.Change(ctx, scope, revived)
	if err != nil || fifth.Deleted || fifth.DocumentVersion != 5 || fifth.ACLRevision != 3 {
		t.Fatal("revive preserves version monotonicity", fifth, err)
	}
	requireSourceCount(t, p.DB, scope, "platform_knowledge_document_version", 5)
	requireSourceCount(t, p.DB, scope, "knowledge_source_fixture_audit", 5)
	noMetadata := sourceCommand("optional-metadata", "optional", 5, 0)
	noMetadata.Metadata = nil
	noMetadata.ACL.Readers = nil
	if _, err := p.Change(ctx, scope, noMetadata); err != nil {
		t.Fatal(err)
	}
	if document, err := p.ReadVersion(ctx, scope, "optional-metadata", 1); err != nil || document.Body != noMetadata.Body {
		t.Fatal("optional metadata canonical digest", document, err)
	}
	fresh, err := sql.Open("pgx", os.Getenv("KNOWLEDGE_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	reopened := PostgresSource{DB: fresh}
	page, err = reopened.EventsAfter(ctx, scope, 0, 10)
	if err != nil || page.HeadRevision != 6 || len(page.Events) != 6 {
		t.Fatal("reopened source lost committed event prefix", page, err)
	}
	if document, err := reopened.ReadVersion(ctx, scope, "document", 1); err != nil || document.Body != command.Body {
		t.Fatal("reopened source lost immutable version", document, err)
	}
}

func TestPostgresSourceAuditRollbackAndRetry(t *testing.T) {
	p, scope, _ := sourceFixture(t)
	ctx := context.Background()
	if _, err := p.Change(ctx, scope, sourceCommand("document", "create", 0, 0)); err != nil {
		t.Fatal(err)
	}
	recorder := p.RecordChange
	fault := errors.New("injected source audit failure")
	p.RecordChange = func(ctx context.Context, tx *sql.Tx, s ProjectionScope, r SourceReceipt) error {
		if err := recorder(ctx, tx, s, r); err != nil {
			return err
		}
		return fault
	}
	change := sourceCommand("document", "retry-after-fault", 1, 1)
	change.Body = "updated"
	if r, err := p.Change(ctx, scope, change); !errors.Is(err, fault) || r != (SourceReceipt{}) {
		t.Fatal("failed change returned receipt", r, err)
	}
	for _, table := range []string{"platform_knowledge_source_event", "platform_knowledge_document_version", "platform_knowledge_document_head", "knowledge_source_fixture_audit"} {
		requireSourceCount(t, p.DB, scope, table, 1)
	}
	snapshot, err := p.Snapshot(ctx, scope, 10)
	if err != nil || snapshot.Revision != 1 || snapshot.Documents[0].Version != 1 {
		t.Fatal("failed audit advanced source", snapshot, err)
	}
	p.RecordChange = recorder
	if r, err := p.Change(ctx, scope, change); err != nil || r.SourceRevision != 2 {
		t.Fatal("retry consumed source revision", r, err)
	}
	page, err := p.EventsAfter(ctx, scope, 0, 10)
	if err != nil || len(page.Events) != 2 || page.Events[1].SourceRevision != 2 {
		t.Fatal("rollback left a cursor gap", page, err)
	}
}

func TestPostgresSourceConcurrentReplayAndCAS(t *testing.T) {
	p, scope, _ := sourceFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	recorder := p.RecordChange
	p.RecordChange = func(ctx context.Context, tx *sql.Tx, s ProjectionScope, r SourceReceipt) error {
		calls.Add(1)
		return recorder(ctx, tx, s, r)
	}
	command := sourceCommand("document", "concurrent-create", 0, 0)
	results := make(chan SourceReceipt, 8)
	failures := make(chan error, 8)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); r, err := p.Change(ctx, scope, command); results <- r; failures <- err }()
	}
	workers.Wait()
	close(results)
	close(failures)
	var first SourceReceipt
	for r := range results {
		if first.SourceRevision == 0 {
			first = r
		}
		if r != first {
			t.Fatal("replay diverged", r, first)
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate transactional records", calls.Load())
	}
	var successes, conflicts atomic.Int32
	for _, id := range []string{"next-a", "next-b"} {
		workers.Add(1)
		go func(id string) {
			defer workers.Done()
			_, err := p.Change(ctx, scope, sourceCommand(id, id, 1, 0))
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrSourceConflict) {
				conflicts.Add(1)
			} else {
				t.Error(err)
			}
		}(id)
	}
	workers.Wait()
	if successes.Load() != 1 || conflicts.Load() != 1 {
		t.Fatal("source CAS lost update", successes.Load(), conflicts.Load())
	}
	requireSourceCount(t, p.DB, scope, "platform_knowledge_source_event", 2)
	requireSourceCount(t, p.DB, scope, "knowledge_source_fixture_audit", 2)
}

func TestPostgresSourceCommitOrderAndSnapshot(t *testing.T) {
	p, scope, admin := sourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := p.Change(ctx, scope, sourceCommand("document", "initial", 0, 0)); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	recorder := p.RecordChange
	p.RecordChange = func(ctx context.Context, tx *sql.Tx, s ProjectionScope, r SourceReceipt) error {
		if err := recorder(ctx, tx, s, r); err != nil {
			return err
		}
		if r.SourceRevision == 2 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := p.Change(ctx, scope, sourceCommand("document", "pending-second", 1, 1))
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	snapshot, err := p.Snapshot(ctx, scope, 10)
	if err != nil || snapshot.Revision != 1 || snapshot.Documents[0].Version != 1 {
		t.Fatal("snapshot included uncommitted document", snapshot, err)
	}
	page, err := p.EventsAfter(ctx, scope, 0, 10)
	if err != nil || page.HeadRevision != 1 || len(page.Events) != 1 {
		t.Fatal("event cursor passed pending transaction", page, err)
	}
	secondDone := make(chan error, 1)
	go func() {
		_, err := p.Change(ctx, scope, sourceCommand("document", "pending-third", 2, 2))
		secondDone <- err
	}()
	// Confirm PostgreSQL itself sees the next writer waiting for the head lock.
	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	for {
		var waiting int
		if err := admin.QueryRowContext(waitCtx, `SELECT COUNT(*) FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%platform_knowledge_source_head%FOR UPDATE%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-waitCtx.Done():
			t.Fatal("next writer never waited for committed predecessor")
		}
	}
	select {
	case err := <-secondDone:
		t.Fatal("later revision escaped head lock", err)
	default:
	}
	unblock()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	page, err = p.EventsAfter(ctx, scope, 1, 10)
	if err != nil || page.HeadRevision != 3 || len(page.Events) != 2 || page.Events[0].SourceRevision != 2 || page.Events[1].SourceRevision != 3 {
		t.Fatal("commit-order event prefix", page, err)
	}
}

func TestPostgresSourceContinuityAndScope(t *testing.T) {
	p, scope, admin := sourceFixture(t)
	ctx := context.Background()
	for i, key := range []string{"one", "two", "three"} {
		if _, err := p.Change(ctx, scope, sourceCommand(key, key, int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Snapshot(ctx, scope, 2); !errors.Is(err, ErrCorpusLimit) {
		t.Fatal("truncated source snapshot accepted", err)
	}
	if _, err := p.EventsAfter(ctx, scope, 4, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("future cursor accepted", err)
	}
	foreign := scope
	foreign.ApplicationID = "another-application"
	snapshot, err := p.Snapshot(ctx, foreign, 10)
	if err != nil || snapshot.Revision != 0 || len(snapshot.Documents) != 0 {
		t.Fatal("foreign source head leaked", snapshot, err)
	}
	if _, err := p.ReadVersion(ctx, foreign, "one", 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("foreign version leaked", err)
	}
	// Event receipts must agree with their indexed immutable source version.
	if _, err := admin.Exec(`UPDATE platform_knowledge_source_event SET receipt=jsonb_set(receipt,'{document_version}','999'::jsonb) WHERE tenant_id=$1 AND source_revision=1`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EventsAfter(ctx, scope, 0, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupt source event receipt accepted", err)
	}
	if _, err := p.Change(ctx, scope, sourceCommand("one", "one", 0, 0)); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupt source replay accepted", err)
	}
	if _, err := admin.Exec(`UPDATE platform_knowledge_source_event SET receipt=jsonb_set(receipt,'{document_version}','1'::jsonb) WHERE tenant_id=$1 AND source_revision=1`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	// Simulate operator/database corruption, not a supported source API.
	if _, err := admin.Exec(`DELETE FROM platform_knowledge_source_event WHERE tenant_id=$1 AND source_revision=2`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EventsAfter(ctx, scope, 0, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("missing committed event silently skipped", err)
	}
	if _, err := admin.Exec(`UPDATE platform_knowledge_document_version SET payload=jsonb_set(payload,'{body}','"corrupted"'::jsonb) WHERE tenant_id=$1 AND document_id='one'`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(ctx, scope, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupt source payload accepted", err)
	}
	if _, err := p.Change(ctx, scope, sourceCommand("one", "one", 0, 0)); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("replay returned corrupt document receipt", err)
	}
}

func TestPostgresSourceRequiresRecorderAndDMLOnly(t *testing.T) {
	p, scope, _ := sourceFixture(t)
	ctx := context.Background()
	missing := p
	missing.RecordChange = nil
	if _, err := missing.Change(ctx, scope, sourceCommand("document", "missing-recorder", 0, 0)); !errors.Is(err, ErrSourceRecorderUnavailable) {
		t.Fatal("unrecorded source mutation admitted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Change(canceled, scope, sourceCommand("document", "canceled", 0, 0)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled source change", err)
	}
	for _, ddl := range []string{`CREATE TABLE forbidden_source_runtime_ddl(id INT)`, `CREATE TEMP TABLE forbidden_source_runtime_temp(id INT)`, `ALTER TABLE platform_knowledge_document_head ADD COLUMN forbidden INT`, `CREATE TABLE knowledge.forbidden_source_runtime_ddl(id INT)`} {
		if _, err := p.DB.Exec(ddl); err == nil {
			t.Fatal("source runtime can issue DDL", ddl)
		}
	}
	if _, err := p.Change(ctx, scope, sourceCommand("document", "valid", 0, 0)); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SourceChange){func(c *SourceChange) { c.ACL.Readers = []string{"same", "same"} }, func(c *SourceChange) { c.Body = "" }, func(c *SourceChange) { c.Deleted = true }, func(c *SourceChange) { c.ExpectedSourceRevision = -1 }} {
		command := sourceCommand("invalid", "invalid", 1, 0)
		mutate(&command)
		if _, err := p.Change(ctx, scope, command); !errors.Is(err, ErrInvalidProjection) {
			t.Fatal("invalid source command", err)
		}
	}
	requireSourceCount(t, p.DB, scope, "platform_knowledge_source_event", 1)
}
