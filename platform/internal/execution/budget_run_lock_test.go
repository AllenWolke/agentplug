package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestBudgetRunReadTxDoesNotWaitOnActorUpdate(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := fmt.Sprintf("actor-read-%d", time.Now().UnixNano())
	scope := testScope(id).domain()
	scope.SessionID = id
	raw := []byte(`{"protocol_version":"execution.v2"}`)
	if _, err = store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture", RequestJSON: raw}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM platform_execution_run WHERE run_id=$1`, id)
	})
	holder, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err = store.BudgetRunForUpdateTx(ctx, holder, id); err != nil {
		t.Fatal(err)
	}
	reader, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	defer readCancel()
	facts, err := store.BudgetRunReadTx(readCtx, reader, id)
	if err != nil || facts.Scope.RunID != id {
		t.Fatalf("unlocked actor read waited or missed the row: facts=%+v err=%v", facts.Scope.RunID, err)
	}
	shareCtx, shareCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer shareCancel()
	_, err = store.BudgetRunTx(shareCtx, reader, id)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FOR SHARE on the locked actor must wait, got %v", err)
	}
}
