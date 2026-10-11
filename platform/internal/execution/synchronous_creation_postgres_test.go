package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestSQLSynchronousCreationCannotRaceCancelledParentPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	db := f.runs.DB()
	ctx := f.ctx
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS evaluation_creation_fixture(id TEXT PRIMARY KEY,status TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	parent := f.id + "-parent"
	if _, err := db.ExecContext(ctx, `INSERT INTO evaluation_creation_fixture VALUES($1,'running')`, parent); err != nil {
		t.Fatal(err)
	}
	if err := f.runs.SetSynchronousCreationGuard(func(ctx context.Context, tx *sql.Tx, r platformruntime.CreateRequest) error {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM evaluation_creation_fixture WHERE id=$1 FOR UPDATE`, r.Scope.ParentRunID).Scan(&state); err != nil {
			return err
		}
		if state != "running" {
			return contract.ErrPermissionDenied
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id := f.id + "-new-child"
	scope := testScope(id).domain()
	scope.ParentRunID = parent
	scope.SessionID = id
	raw, _ := json.Marshal(contract.ExecuteRequest{Scope: contract.ScopeKey{ParentRunID: parent}})
	request := platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id, RequestJSON: raw}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE evaluation_creation_fixture SET status='cancelling' WHERE id=$1`, parent); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := f.runs.Create(request); done <- err }()
	select {
	case err := <-done:
		t.Fatal("creation bypassed parent stop lock", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, contract.ErrPermissionDenied) {
			t.Fatal("cancelled parent admitted a late child", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("creation remained blocked")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_run WHERE run_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected child left a durable run", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected child left events", err)
	}
}

func TestSQLSynchronousCreationCommitIsVisibleBeforeParentStopPostgres(t *testing.T) {
	f := newCancellationFixture(t)
	db := f.runs.DB()
	ctx := f.ctx
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS evaluation_creation_fixture(id TEXT PRIMARY KEY,status TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	parent := f.id + "-parent"
	if _, err := db.ExecContext(ctx, `INSERT INTO evaluation_creation_fixture VALUES($1,'running')`, parent); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if err := f.runs.SetSynchronousCreationGuard(func(ctx context.Context, tx *sql.Tx, r platformruntime.CreateRequest) error {
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM evaluation_creation_fixture WHERE id=$1 FOR UPDATE`, r.Scope.ParentRunID).Scan(&state); err != nil {
			return err
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}); err != nil {
		t.Fatal(err)
	}
	id := f.id + "-early-child"
	scope := testScope(id).domain()
	scope.ParentRunID = parent
	scope.SessionID = id
	raw, _ := json.Marshal(contract.ExecuteRequest{Scope: contract.ScopeKey{ParentRunID: parent}})
	request := platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id, RequestJSON: raw}
	created := make(chan error, 1)
	go func() { _, err := f.runs.Create(request); created <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("creation did not acquire parent fence")
	}
	stopped := make(chan error, 1)
	go func() {
		_, err := db.ExecContext(ctx, `UPDATE evaluation_creation_fixture SET status='cancelling' WHERE id=$1`, parent)
		stopped <- err
	}()
	select {
	case err := <-stopped:
		t.Fatal("parent stop passed uncommitted child admission", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-created:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child commit remained blocked")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parent stop remained blocked")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_run WHERE run_id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatal("cancellation cannot enumerate the admitted child", err)
	}
}
