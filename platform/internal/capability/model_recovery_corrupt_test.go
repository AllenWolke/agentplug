package capability

import (
	"context"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"strings"
	"testing"
	"time"
)

// A malformed envelope cannot starve valid rows or release an unknown charge.
// 损坏意图不能阻塞有效记录，也不能释放可能已经计费的预算。
func TestSQLBillingRecoveryCorruptRowIsIsolated(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope, fp := strings.Repeat("c", 64), strings.Repeat("d", 64)
	bad, good := fmt.Sprintf("corrupt-%d", time.Now().UnixNano()), fmt.Sprintf("valid-%d", time.Now().UnixNano())
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key IN (?,?)`), scope, bad, good); err != nil {
			t.Error("fixture cleanup failed")
		}
	}()
	for _, key := range []string{bad, good} {
		if _, _, err := store.Reserve(ctx, scope, key, fp, 0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',billing_state='pending',billing_recovery_json=?,updated_at=clock_timestamp()-INTERVAL '1 day' WHERE scope_hash=? AND idempotency_key=?`), `"invalid-envelope"`, scope, key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_recovery_json='{}' WHERE scope_hash=? AND idempotency_key=?`), scope, good); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListBillingRecovery(ctx, 64)
	if err != nil {
		t.Fatal("one corrupt row stopped the whole page")
	}
	var foundBad, foundGood bool
	for _, row := range rows {
		if row.Key == bad {
			foundBad = row.RecoveryCorrupt && row.Recovery == nil && row.Response == nil
		}
		if row.Key == good {
			foundGood = !row.RecoveryCorrupt && row.Recovery != nil
		}
	}
	if !foundBad || !foundGood {
		t.Fatal("row isolation lost valid work or leaked corrupt payload")
	}
	if err := store.DeferBillingRecovery(ctx, scope, bad, fp); err != nil {
		t.Fatal(err)
	}
	rows, err = store.ListBillingRecovery(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	foundGood = false
	for _, row := range rows {
		if row.Key == bad {
			t.Fatal("corrupt row was not backed off")
		}
		if row.Key == good {
			foundGood = true
		}
	}
	if !foundGood {
		t.Fatal("backoff removed unrelated valid row")
	}
}
