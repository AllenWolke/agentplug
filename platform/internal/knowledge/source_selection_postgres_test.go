package knowledge

import (
	"context"
	"errors"
	"testing"
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
