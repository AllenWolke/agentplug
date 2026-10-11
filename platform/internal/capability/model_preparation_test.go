package capability

import (
	"context"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExpiredPreparationCannotOverwriteReplacement(t *testing.T) {
	ctx := context.Background()
	store := newMemoryModelInvocationStore()
	original, _, err := store.ReserveGoverned(ctx, "scope", "key", "fp")
	if err != nil || original.AttemptToken == "" {
		t.Fatal("preparation missing")
	}
	// Advance only the fixture deadline, not the real production clock.
	// 仅调整本测试记录的期限，生产时间不注入人为偏差。
	store.mu.Lock()
	r := store.records["scope\x00key"]
	r.PreparationUntil = time.Now().Add(-time.Second)
	store.records["scope\x00key"] = r
	store.mu.Unlock()
	count, err := store.RecoverExpiredPreparations(ctx)
	if err != nil || count != 1 {
		t.Fatal("expired unsent preparation not recovered")
	}
	replacement, _, err := store.ReserveGoverned(ctx, "scope", "key", "fp")
	if err != nil || replacement.AttemptToken == original.AttemptToken {
		t.Fatal("retry reused an old execution nonce")
	}
	if err := store.FailPreparation(ctx, "scope", "key", "fp", original.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("old request failed replacement")
	}
	if err := store.SaveBillingRecovery(ctx, "scope", "key", "fp", nil, 0, BillingRecovery{AttemptToken: original.AttemptToken, SendDeadline: time.Now().Add(time.Minute)}); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("old request took over replacement")
	}
	if err := store.SaveBillingRecovery(ctx, "scope", "key", "fp", nil, 0, BillingRecovery{AttemptToken: replacement.AttemptToken, SendDeadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if count, err := store.RecoverExpiredPreparations(ctx); err != nil || count != 0 {
		t.Fatal("prepared send was made retryable")
	}
}

func TestPreparationRecoveryIsBoundedAndDoesNotTouchUnownedCalls(t *testing.T) {
	ctx := context.Background()
	store := newMemoryModelInvocationStore()
	for i := 0; i < 17; i++ {
		key := fmt.Sprintf("key-%d", i)
		if _, _, err := store.ReserveGoverned(ctx, "scope", key, "fp"); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.Lock()
	for key, r := range store.records {
		r.PreparationUntil = time.Now().Add(-time.Second)
		store.records[key] = r
	}
	store.mu.Unlock()
	if _, _, err := store.Reserve(ctx, "scope", "non-governed", "fp", 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveGoverned(ctx, "scope", "live", "fp"); err != nil {
		t.Fatal(err)
	}
	if n, err := store.RecoverExpiredPreparations(ctx); err != nil || n != 16 {
		t.Fatal("recovery batch was not bounded")
	}
	if n, err := store.RecoverExpiredPreparations(ctx); err != nil || n != 1 {
		t.Fatal("recovery did not drain remaining expired record")
	}
	if _, _, err := store.Reserve(ctx, "scope", "non-governed", "fp", 0, 0); !errors.Is(err, ErrModelInvocationPending) {
		t.Fatal("unowned call was made retryable")
	}
	if _, _, err := store.ReserveGoverned(ctx, "scope", "live", "fp"); !errors.Is(err, ErrModelInvocationPending) {
		t.Fatal("live preparation was made retryable")
	}
}

func TestSQLPreparingCrashRecoveryFencesStaleAttempt(t *testing.T) {
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
	if err != nil || store.EnsureSchema(ctx) != nil {
		t.Fatal("schema unavailable")
	}
	scope, fp, id := strings.Repeat("a", 64), strings.Repeat("b", 64), fmt.Sprintf("prepare-crash-%d", time.Now().UnixNano())
	original, _, err := store.ReserveGoverned(ctx, scope, id, fp)
	if err != nil || original.AttemptToken == "" {
		t.Fatal("durable nonce missing")
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET preparation_deadline=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND idempotency_key=? AND invocation_token=?`), scope, id, original.AttemptToken); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLModelInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := reopened.RecoverExpiredPreparations(ctx); err != nil || n != 1 {
		t.Fatal("SQL expired preparation not recovered")
	}
	replacement, _, err := reopened.ReserveGoverned(ctx, scope, id, fp)
	if err != nil || replacement.AttemptToken == original.AttemptToken {
		t.Fatal("restart reused invocation nonce")
	}
	if err := store.FailPreparation(ctx, scope, id, fp, original.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("stale producer failed new preparation")
	}
	if err := store.SaveBillingRecovery(ctx, scope, id, fp, nil, 0, BillingRecovery{AttemptToken: original.AttemptToken, SendDeadline: time.Now().Add(time.Minute)}); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("stale producer updated new send intent")
	}
	if err := reopened.SaveBillingRecovery(ctx, scope, id, fp, nil, 0, BillingRecovery{AttemptToken: replacement.AttemptToken, SendDeadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if n, err := reopened.RecoverExpiredPreparations(ctx); err != nil || n != 0 {
		t.Fatal("inflight request reverted to retryable")
	}
}

// Concurrent recovery takes bounded, disjoint locked batches and never changes
// a live preparation, an unowned legacy call, or a submitted request.
func TestSQLPreparationRecoveryConcurrentBoundedBatches(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := fmt.Sprintf("preparation-batch-%d", time.Now().UnixNano())
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_model_invocation WHERE scope_hash=?`), scope); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 32; i++ {
		key := fmt.Sprintf("expired-%02d", i)
		if _, _, err = store.ReserveGoverned(ctx, scope, key, "fp"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET preparation_deadline=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND idempotency_key=?`), scope, key); err != nil {
			t.Fatal(err)
		}
	}
	live, _, err := store.ReserveGoverned(ctx, scope, "live", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Reserve(ctx, scope, "legacy", "fp", 0, 0); err != nil {
		t.Fatal(err)
	}
	submitted, _, err := store.ReserveGoverned(ctx, scope, "submitted", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveBillingRecovery(ctx, scope, "submitted", "fp", nil, 0, BillingRecovery{AttemptToken: submitted.AttemptToken, SendDeadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	counts := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := store.RecoverExpiredPreparations(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if n < 0 || n > 16 {
				t.Errorf("unbounded recovery batch: %d", n)
			}
			counts <- n
		}()
	}
	wg.Wait()
	close(counts)
	var total int64
	for n := range counts {
		total += n
	}
	if total != 32 {
		t.Fatalf("concurrent recovery count: got %d, want 32", total)
	}
	if n, err := store.RecoverExpiredPreparations(ctx); err != nil || n != 0 {
		t.Fatal("recovery duplicated work or changed protected requests", err)
	}
	var recovered int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_invocation WHERE scope_hash=? AND status='failed' AND invocation_token='' AND preparation_deadline IS NULL`), scope).Scan(&recovered); err != nil || recovered != 32 {
		t.Fatal("durable recovered rows mismatch", err)
	}
	var token string
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT invocation_token FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key='live' AND status='running' AND billing_state='preparing'`), scope).Scan(&token); err != nil || token != live.AttemptToken {
		t.Fatal("live preparation changed", err)
	}
	if _, _, err = store.Reserve(ctx, scope, "legacy", "fp", 0, 0); !errors.Is(err, ErrModelInvocationPending) {
		t.Fatal("unowned invocation became retryable", err)
	}
	if err = store.FailPreparation(ctx, scope, "submitted", "fp", submitted.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("submitted invocation became an unsent preparation", err)
	}
}
