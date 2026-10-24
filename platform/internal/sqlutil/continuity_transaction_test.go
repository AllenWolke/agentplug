package sqlutil

import (
	"context"
	"database/sql"
	"testing"
)

func TestContinuityTransactionPreservesOwnerAndRejectsForeignBinding(t *testing.T) {
	owner, foreign := new(sql.DB), new(sql.DB)
	tx := new(sql.Tx)
	ctx, cancel := context.WithCancel(context.Background())
	bound := WithContinuityTransaction(ctx, owner, tx)
	if got, ok, err := ContinuityTransaction(bound, owner); got != tx || !ok || err != nil {
		t.Fatal(got, ok, err)
	}
	cancel()
	if bound.Err() != context.Canceled {
		t.Fatal("binding lost caller cancellation")
	}
	for _, ctx := range []context.Context{bound, WithContinuityTransaction(context.Background(), owner, nil)} {
		if _, ok, err := ContinuityTransaction(ctx, foreign); !ok || err == nil {
			t.Fatal("foreign/invalid binding silently fell back")
		}
	}
	if _, ok, err := ContinuityTransaction(context.Background(), owner); ok || err != nil {
		t.Fatal("absent binding changed legacy behavior")
	}
	if WithContinuityTransaction(nil, owner, tx) != nil {
		t.Fatal("nil context invented a live caller")
	}
}
