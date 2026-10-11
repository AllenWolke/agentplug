package capability

import (
	"context"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"sync"
	"testing"
	"time"
)

// Exercise PostgreSQL's lock wait and predicate recheck, rather than timing a mock.
// 实际验证 PostgreSQL 等锁后重新检查条件，避免以 Mock 或睡眠代替并发清理证据。
func TestSQLMemoryExpiryCleanupPreservesConcurrentRefresh(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated Postgres fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := NewSQLMemoryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("expiry-refresh-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_memory_entry WHERE scope_key=?`), memoryHash(key))
	if err := store.Save(ctx, key, memoryEntry{Value: map[string]any{"generation": "expired"}, ExpiresAt: time.Now().Add(-time.Hour)}, 0); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_memory_entry SET value_json=?,expires_at=? WHERE scope_key=?`), `{"generation":"refreshed"}`, time.Now().Add(time.Hour), memoryHash(key)); err != nil {
		t.Fatal(err)
	}
	loaded := make(chan error, 1)
	go func() {
		_, _, err := store.Load(ctx, key)
		loaded <- err
	}()
	// The non-locking read observes the old expired value. Its cleanup must
	// actually wait for the uncommitted refresh before we release that lock.
	// 非锁定读取看到旧过期值；确认清理正等待刷新事务后再提交，确保竞态实际发生。
	for {
		var waiting int
		err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM pg_stat_activity a WHERE a.datname=current_database() AND cardinality(pg_blocking_pids(a.pid))>0 AND a.query LIKE '%DELETE FROM platform_memory_entry%'`)).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case err := <-loaded:
			t.Fatalf("cleanup returned before waiting for refresh: %v", err)
		case <-ctx.Done():
			t.Fatal("cleanup did not enter the expected PostgreSQL lock wait")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-loaded; err != nil {
		t.Fatal(err)
	}
	entry, ok, err := store.Load(ctx, key)
	if err != nil || !ok || entry.Value["generation"] != "refreshed" {
		t.Fatalf("concurrent refresh was erased: present=%v value=%v err=%v", ok, entry.Value, err)
	}
}

func TestSQLMemoryConcurrentQuotaCannotOverrun(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx := context.Background()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLMemoryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("pg-memory-quota-%d\x00", time.Now().UnixNano())
	start := make(chan struct{})
	results := make(chan error, 20)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			results <- store.Save(ctx, fmt.Sprintf("%skey-%d", prefix, i), memoryEntry{Value: map[string]any{"i": i}, ExpiresAt: time.Now().Add(time.Hour)}, 3)
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	saved, limited := 0, 0
	for err := range results {
		if err == nil {
			saved++
		} else if errors.Is(err, errMemoryLimitExceeded) {
			limited++
		} else {
			t.Errorf("quota save: %v", err)
		}
	}
	if saved != 3 || limited != 17 {
		t.Fatalf("quota race: saved=%d limited=%d", saved, limited)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_memory_entry WHERE scope_prefix=?`), memoryHash(prefix)).Scan(&count); err != nil || count != 3 {
		t.Fatalf("quota rows=%d err=%v", count, err)
	}
}
