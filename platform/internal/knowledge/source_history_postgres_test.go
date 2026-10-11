package knowledge

import (
	"context"
	"errors"
	"testing"
)

func TestPostgresSourceHistoricalSnapshotsForRecovery(t *testing.T) {
	p, scope, admin := sourceFixture(t)
	ctx := context.Background()
	a := sourceCommand("a", "a", 0, 0)
	if _, err := p.Change(ctx, scope, a); err != nil {
		t.Fatal(err)
	}
	b := sourceCommand("b", "b", 1, 0)
	if _, err := p.Change(ctx, scope, b); err != nil {
		t.Fatal(err)
	}
	a.IdempotencyKey = "a-changed"
	a.ExpectedSourceRevision = 2
	a.ExpectedDocumentVersion = 1
	a.Body = "new body"
	a.ACL.Readers = []string{"different-reader"}
	if _, err := p.Change(ctx, scope, a); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Change(ctx, scope, SourceChange{DocumentID: "b", ActorPrincipalID: "admin", IdempotencyKey: "delete", ExpectedSourceRevision: 3, ExpectedDocumentVersion: 1, Deleted: true}); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		revision int64
		count    int
		aVersion int64
		bDeleted bool
	}{{0, 0, 0, false}, {1, 1, 1, false}, {2, 2, 1, false}, {3, 2, 2, false}, {4, 2, 2, true}} {
		snapshot, err := p.SnapshotAt(ctx, scope, step.revision, 10)
		if err != nil || snapshot.Revision != step.revision || len(snapshot.Documents) != step.count {
			t.Fatal("historical snapshot", step, snapshot, err)
		}
		if step.count > 0 && snapshot.Documents[0].Version != step.aVersion {
			t.Fatal("history included later version", snapshot)
		}
		if step.count == 2 && snapshot.Documents[1].Deleted != step.bDeleted {
			t.Fatal("history changed tombstone boundary", snapshot)
		}
	}
	current, err := p.Snapshot(ctx, scope, 10)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := p.SnapshotAt(ctx, scope, 4, 10)
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, _ := sourceDigest(current)
	capturedDigest, _ := sourceDigest(captured)
	if currentDigest != capturedDigest {
		t.Fatal("current and historical snapshot digests disagree")
	}
	if _, err := p.SnapshotAt(ctx, scope, 5, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("future recovery revision admitted", err)
	}
	if _, err := p.SnapshotAt(ctx, scope, 2, 1); !errors.Is(err, ErrCorpusLimit) {
		t.Fatal("partial recovery snapshot admitted", err)
	}
	foreign := scope
	foreign.ApplicationID = "foreign"
	if snapshot, err := p.SnapshotAt(ctx, foreign, 0, 10); err != nil || len(snapshot.Documents) != 0 {
		t.Fatal("foreign historical snapshot", snapshot, err)
	}
	if _, err := p.SnapshotAt(ctx, foreign, 1, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("foreign revision existed", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.SnapshotAt(canceled, scope, 1, 10); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled history read", err)
	}
	if _, err := admin.Exec(`DELETE FROM platform_knowledge_source_event WHERE tenant_id=$1 AND source_revision=2`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SnapshotAt(ctx, scope, 3, 10); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("historical snapshot ignored event gap", err)
	}
	// A gap after the target does not invalidate an earlier committed prefix.
	if _, err := p.SnapshotAt(ctx, scope, 1, 10); err != nil {
		t.Fatal("later gap invalidated earlier snapshot", err)
	}
}
