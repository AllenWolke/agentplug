package knowledge

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
)

func TestPostgresIndexBuildReplayVerifiesImmutableContent(t *testing.T) {
	c, scope, admin, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	vectors := indexFixtureVectors(plan)
	// Concurrent retries wait on the unique generation insert and acknowledge
	// the same complete committed rows; they never overwrite another manifest.
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- c.BuildOrReplay(ctx, plan, "recoverable", vectors) }()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent exact build", err)
		}
	}
	changed := indexFixtureVectors(plan)
	for id := range changed {
		changed[id] = []float32{0.5, 1}
		break
	}
	if err := c.BuildOrReplay(ctx, plan, "recoverable", changed); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("changed embedding replay", err)
	}
	if err := c.Build(ctx, plan, "recoverable", vectors); err == nil {
		t.Fatal("strict Build unexpectedly replayed")
	}
	if _, err := admin.Exec(`UPDATE knowledge.chunks SET body='tampered' WHERE tenant_id=$1 AND generation_id='recoverable'`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := c.BuildOrReplay(ctx, plan, "recoverable", vectors); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupt stored rows replayed", err)
	}
}

func TestPostgresIndexPublicationReplayPreservesFenceAndAudit(t *testing.T) {
	c, scope, _, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	vectors := indexFixtureVectors(plan)
	raw, err := plan.Checkpoint(vectors)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BuildOrReplay(ctx, plan, "first", vectors); err != nil {
		t.Fatal(err)
	}
	if rev, err := c.PublishOrReplay(ctx, plan, "first"); err != nil || rev != 1 {
		t.Fatal(rev, err)
	}
	// Simulate lost task acknowledgment: recreate the plan from durable state.
	restored, err := c.Restore(ctx, scope, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BuildOrReplay(ctx, restored, "first", nil); err != nil {
		t.Fatal(err)
	}
	if rev, err := c.PublishOrReplay(ctx, restored, "first"); err != nil || rev != 1 {
		t.Fatal("recovered acknowledgment", rev, err)
	}
	var count int
	if err := c.Source.DB.QueryRow(`SELECT COUNT(*) FROM knowledge_index_fixture_audit WHERE tenant_id=$1`, scope.TenantID).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate publication audit", count, err)
	}
	if _, err := c.Publish(ctx, restored, "first"); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("strict Publish unexpectedly replayed", err)
	}
	denied := errors.New("live authority revoked")
	c.GuardPublishTx = func(context.Context, *sql.Tx, ProjectionScope) error { return denied }
	if _, err := c.PublishOrReplay(ctx, restored, "first"); !errors.Is(err, denied) {
		t.Fatal("replay bypassed current authority", err)
	}
	c.GuardPublishTx = nil
	newer, err := c.Prepare(ctx, scope, config, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BuildOrReplay(ctx, newer, "second", nil); err != nil {
		t.Fatal(err)
	}
	if rev, err := c.PublishOrReplay(ctx, newer, "second"); err != nil || rev != 2 {
		t.Fatal(rev, err)
	}
	if _, err := c.PublishOrReplay(ctx, restored, "first"); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("old generation reactivated", err)
	}
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "changed", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PublishOrReplay(ctx, newer, "second"); !errors.Is(err, ErrSourceConflict) {
		t.Fatal("obsolete source replay acknowledged", err)
	}
}

func TestPostgresIndexPublicationReplayRechecksAfterLocks(t *testing.T) {
	c, scope, admin, config := indexFixture(t)
	ctx := context.Background()
	if _, err := c.Source.Change(ctx, scope, sourceCommand("a", "a", 0, 0)); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BuildOrReplay(ctx, plan, "first", indexFixtureVectors(plan)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PublishOrReplay(ctx, plan, "first"); err != nil {
		t.Fatal(err)
	}
	checks := 0
	denied := errors.New("expired after waiting for locks")
	c.GuardPublishTx = func(context.Context, *sql.Tx, ProjectionScope) error {
		checks++
		if checks == 2 {
			return denied
		}
		return nil
	}
	if _, err := c.PublishOrReplay(ctx, plan, "first"); !errors.Is(err, denied) || checks != 2 {
		t.Fatal("no final authority check", checks, err)
	}
	if _, err := admin.Exec(`UPDATE knowledge.generations SET embedding_model_version='different' WHERE tenant_id=$1 AND generation_id='first'`, scope.TenantID); err != nil {
		t.Fatal(err)
	}
	c.GuardPublishTx = nil
	if _, err := c.PublishOrReplay(ctx, plan, "first"); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("corrupt generation metadata replayed", err)
	}
}
