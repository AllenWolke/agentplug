package execution

import (
	"context"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestSQLRecoverySnapshotReadsPersistedStates(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx := context.Background()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	before, err := store.RecoverySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"cancelling", "recovering"} {
		id := fmt.Sprintf("recovery-snapshot-%s-%d", status, time.Now().UnixNano())
		scope := testScope(id)
		scope.SessionID = id
		if _, err := store.Create(platformruntime.CreateRequest{
			ID: id, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "snapshot",
		}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			for _, table := range []string{"platform_execution_creation_projection", "platform_execution_event", "platform_execution_run"} {
				if _, err := store.db.Exec(sqlutil.Bind(`DELETE FROM `+table+` WHERE run_id=?`), id); err != nil {
					t.Error(err)
				}
			}
		}()
		if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status=?,updated_at=? WHERE run_id=?`), status, time.Now().UTC().Add(-10*time.Minute), id); err != nil {
			t.Fatal(err)
		}
	}
	after, err := store.RecoverySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Cancelling != before.Cancelling+1 || after.Recovering != before.Recovering+1 ||
		!after.OldestCancellingAt.Before(time.Now().Add(-9*time.Minute)) ||
		!after.OldestRecoveringAt.Before(time.Now().Add(-9*time.Minute)) {
		t.Fatalf("durable recovery snapshot failed: before=%+v after=%+v", before, after)
	}
}
