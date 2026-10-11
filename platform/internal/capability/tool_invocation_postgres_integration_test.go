package capability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestToolInvocationFailedAttemptCanRetryPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("PUBLIC_TEST_POSTGRES_MIGRATION_DSN is only set by the isolated Compose E2E")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("connect isolated Postgres: %v", err)
	}
	store, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 12)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	scopeHash := fmt.Sprintf("%x", sha256.Sum256(seed))
	callID := "retry-" + hex.EncodeToString(seed)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte("immutable notification input")))
	defer func() {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scopeHash, callID); err != nil {
			t.Errorf("clean integration ledger row: %v", err)
		}
	}()

	if _, replay, err := store.Reserve(ctx, scopeHash, callID, fingerprint); err != nil || replay {
		t.Fatalf("initial reservation should be new: replay=%v err=%v", replay, err)
	}
	// This fixture models a proven pre-submit refusal, not an ambiguous commit.
	// 本夹具仅模拟可证明未提交的拒绝，不模拟提交结果未知。
	if err := store.Fail(ctx, scopeHash, callID, fingerprint, "TOOL_NOT_SUBMITTED"); err != nil {
		t.Fatal(err)
	}
	if _, replay, err := store.Reserve(ctx, scopeHash, callID, fingerprint); err != nil || replay {
		t.Fatalf("same fingerprint should reclaim failed attempt: replay=%v err=%v", replay, err)
	}
	if _, _, err := store.Reserve(ctx, scopeHash, callID, fingerprint); !errors.Is(err, ErrToolInvocationPending) {
		t.Fatalf("concurrent retry must observe the active reservation, got %v", err)
	}
	result := map[string]any{"event_id": "stable-event", "delivery_status": "pending"}
	if err := store.Complete(ctx, scopeHash, callID, fingerprint, result); err != nil {
		t.Fatal(err)
	}
	replayed, isReplay, err := store.Reserve(ctx, scopeHash, callID, fingerprint)
	if err != nil || !isReplay || replayed.Result["event_id"] != "stable-event" {
		t.Fatalf("completed retry must replay stable result: replay=%v result=%+v err=%v", isReplay, replayed.Result, err)
	}
	unknownID := callID + "-unknown"
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scopeHash, unknownID); err != nil {
			t.Error("unknown fixture cleanup failed")
		}
	}()
	if _, _, err := store.Reserve(ctx, scopeHash, unknownID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkUnknown(ctx, scopeHash, unknownID, fingerprint); err != nil {
		t.Fatal(err)
	}
	// Reconnect to prove this safety boundary is not a process-local lock.
	// 重连数据库，证明该拒绝边界不依赖单进程内存锁。
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLToolInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.Reserve(ctx, scopeHash, unknownID, fingerprint); !errors.Is(err, ErrToolResultUnknown) {
		t.Fatal("unknown result became retryable after reconnect")
	}
	if err := reopened.Fail(ctx, scopeHash, unknownID, fingerprint, "TOOL_NOT_SUBMITTED"); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("unknown result was downgraded to retryable failure")
	}
}
