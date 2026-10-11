package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestPostgresIndexCheckpointRestorePreservesWorkAndCAS(t *testing.T) {
	c, scope, _, config := indexFixture(t)
	ctx := context.Background()
	command := sourceCommand("doc", "create", 0, 0)
	command.Body = "private-body-do-not-save abcdefghijklmnop"
	if _, err := c.Source.Change(ctx, scope, command); err != nil {
		t.Fatal(err)
	}
	plan, err := c.Prepare(ctx, scope, config, false)
	if err != nil {
		t.Fatal(err)
	}
	required := plan.RequiredChunks()
	if len(required) < 2 {
		t.Fatal("fixture too short")
	}
	completed := map[string][]float32{required[0].ID: {1, 0.5}}
	checkpoint, err := plan.Checkpoint(completed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(checkpoint, []byte("private-body-do-not-save")) {
		t.Fatal("checkpoint leaked source body")
	}
	// Reconstruct in a new coordinator instance, without the original plan.
	restarted := IndexCoordinator{Source: c.Source, Projection: c.Projection, RecordPublish: c.RecordPublish}
	restored, err := restarted.Restore(ctx, scope, checkpoint)
	if err != nil || restored.SourceRevision() != 1 || len(restored.RequiredChunks()) != len(required)-1 || restored.ReusedChunks() != 1 {
		t.Fatal("partial work not restored", err)
	}
	vectors := indexFixtureVectors(restored)
	if err := restarted.Build(ctx, restored, "resumed", vectors); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Publish(ctx, restored, "resumed"); err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Restore(ctx, scope, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Build(ctx, again, "stale-cas", indexFixtureVectors(again)); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Publish(ctx, again, "stale-cas"); !errors.Is(err, ErrProjectionConflict) {
		t.Fatal("restore refreshed captured CAS", err)
	}
	var corrupted map[string]any
	if err := json.Unmarshal(checkpoint, &corrupted); err != nil {
		t.Fatal(err)
	}
	corrupted["active_revision"] = 99
	raw, _ := json.Marshal(corrupted)
	if _, err := restarted.Restore(ctx, scope, raw); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatal("corrupt checkpoint accepted", err)
	}
	foreign := scope
	foreign.ApplicationID = "foreign"
	if _, err := restarted.Restore(ctx, foreign, checkpoint); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("cross-scope checkpoint accepted", err)
	}
	command.IdempotencyKey = "changed"
	command.ExpectedSourceRevision = 1
	command.ExpectedDocumentVersion = 1
	if _, err := c.Source.Change(ctx, scope, command); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Restore(ctx, scope, checkpoint); !errors.Is(err, ErrSourceConflict) {
		t.Fatal("obsolete source work resumed", err)
	}
	if _, err := plan.Checkpoint(map[string][]float32{"unknown": {1, 1}}); !errors.Is(err, ErrInvalidProjection) {
		t.Fatal("foreign completion accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := restarted.Restore(canceled, scope, checkpoint); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled restore", err)
	}
}
