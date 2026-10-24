package knowledge

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestPostgresSourceSelectedCurrentSnapshot(t *testing.T) {
	source, scope, _ := sourceFixture(t)
	ctx := context.Background()
	for _, step := range []struct {
		id       string
		revision int64
	}{{"visible", 0}, {"private", 1}} {
		if _, err := source.Change(ctx, scope, sourceCommand(step.id, step.id, step.revision, 0)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := source.SnapshotDocuments(ctx, scope, []string{"missing", "visible"})
	if err != nil || result.Revision != 2 || len(result.Documents) != 1 || result.Documents[0].ID != "visible" || result.Documents[0].Fact().Version != "1" {
		t.Fatal("selected source facts incorrect", err)
	}
	update := sourceCommand("visible", "update", 2, 1)
	update.ACL.ApplicationVisible = true
	if _, err := source.Change(ctx, scope, update); err != nil {
		t.Fatal(err)
	}
	result, err = source.SnapshotDocuments(ctx, scope, []string{"visible"})
	if err != nil || result.Revision != 3 || result.Documents[0].Version != 2 || result.Documents[0].ACLRevision != 2 {
		t.Fatal("stale source version or ACL", err)
	}
	if _, err := source.Change(ctx, scope, SourceChange{DocumentID: "visible", ActorPrincipalID: "source-admin", IdempotencyKey: "delete", ExpectedSourceRevision: 3, ExpectedDocumentVersion: 2, Deleted: true}); err != nil {
		t.Fatal(err)
	}
	result, err = source.SnapshotDocuments(ctx, scope, []string{"visible"})
	if err != nil || len(result.Documents) != 1 || !result.Documents[0].Deleted || result.Documents[0].Body != "" {
		t.Fatal("current tombstone omitted", err)
	}
	foreign := scope
	foreign.ApplicationID = "foreign"
	result, err = source.SnapshotDocuments(ctx, foreign, []string{"visible"})
	if err != nil || len(result.Documents) != 0 {
		t.Fatal("source crossed application", err)
	}
	for _, invalid := range [][]string{nil, {"visible", "visible"}, {" visible"}, {""}} {
		if _, err := source.SnapshotDocuments(ctx, scope, invalid); !errors.Is(err, ErrInvalidProjection) {
			t.Fatal("invalid selection accepted", err)
		}
	}
}

func TestPostgresSourceSelectionJoinsOnlyExactLiveTransaction(t *testing.T) {
	source, scope, other := sourceFixture(t)
	ctx := context.Background()
	if _, err := source.Change(ctx, scope, sourceCommand("doc", "create", 0, 0)); err != nil {
		t.Fatal(err)
	}
	source.DB.SetMaxOpenConns(1)
	tx, err := source.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	bound := sqlutil.WithContinuityTransaction(ctx, source.DB, tx)
	beforeWaits := source.DB.Stats().WaitCount
	got, err := source.SnapshotDocuments(bound, scope, []string{"doc"})
	if err != nil || len(got.Documents) != 1 || source.DB.Stats().WaitCount != beforeWaits {
		t.Fatal("joined source opened another connection", got, err)
	}
	var one int
	if err = tx.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal("source committed caller transaction", err)
	}
	foreign := sqlutil.WithContinuityTransaction(ctx, other, tx)
	if _, err := source.SnapshotDocuments(foreign, scope, []string{"doc"}); err == nil {
		t.Fatal("foreign transaction database was accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.SnapshotDocuments(bound, scope, []string{"doc"}); err == nil {
		t.Fatal("rolled back transaction started a new source read")
	}
	got, err = source.SnapshotDocuments(ctx, scope, []string{"doc"})
	if err != nil || len(got.Documents) != 1 {
		t.Fatal("ordinary source read failed after owner rollback", got, err)
	}
}
