package sqlutil

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestTransactionResourceIdentityIsOrderedBoundedAndNamespaced(t *testing.T) {
	one, err := transactionResourceIDs("owner/v1", []string{"b", "a", "a"})
	two, err2 := transactionResourceIDs("owner/v1", []string{"a", "b"})
	if err != nil || err2 != nil || !reflect.DeepEqual(one, two) || len(one) != 2 || one[0] >= one[1] {
		t.Fatal("resource order or duplicate identity changed", err, err2)
	}
	other, _ := transactionResourceIDs("other/v1", []string{"a", "b"})
	if reflect.DeepEqual(one, other) {
		t.Fatal("namespace aliased")
	}
	for _, keys := range [][]string{nil, {""}, make([]string, 65)} {
		if _, err := transactionResourceIDs("owner/v1", keys); err == nil {
			t.Fatal("unbounded/empty resource accepted")
		}
	}
	if LockTransactionResources(context.Background(), nil, "owner/v1", "a") == nil {
		t.Fatal("missing transaction accepted")
	}
}

func TestPostgresTransactionResourcesFenceAbsentRowsAndRelease(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned native fixture required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := fmt.Sprintf("absent-resource-%d", time.Now().UnixNano())
	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if err := LockTransactionResources(ctx, first, "test/v1", key); err != nil {
		t.Fatal(err)
	}
	// An unrelated resource must proceed while the first transaction remains
	// open. No table/row exists for either key.
	other, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Rollback()
	if err := LockTransactionResources(ctx, other, "test/v1", key+"-other"); err != nil {
		t.Fatal(err)
	}
	if err := other.Commit(); err != nil {
		t.Fatal(err)
	}
	waiter, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Rollback()
	blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop()
	if err := LockTransactionResources(blocked, waiter, "test/v1", key); err == nil || blocked.Err() == nil {
		t.Fatal("same absent resource was not fenced", err)
	}
	_ = waiter.Rollback()
	if err := first.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Cancellation/rollback cannot leak a session-scoped advisory lock.
	next, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Rollback()
	if err := LockTransactionResources(ctx, next, "test/v1", key); err != nil {
		t.Fatal("transaction lock leaked", err)
	}
	if err := next.Commit(); err != nil {
		t.Fatal(err)
	}
}
