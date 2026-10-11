package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestModelReservationRetriesOnlyRolledBackDeadlocks(t *testing.T) {
	for _, cause := range []error{ErrModelBudgetExceeded, ErrModelInvocationConflict, &pgconn.PgError{Code: "55P03"}, errors.New("ambiguous commit")} {
		calls := 0
		_, _, got := retryModelReservation(context.Background(), func() (ModelInvocation, bool, error) { calls++; return ModelInvocation{}, false, cause })
		if calls != 1 || got != cause {
			t.Fatal("unsafe error retried", calls, got)
		}
	}
	calls := 0
	result, _, err := retryModelReservation(context.Background(), func() (ModelInvocation, bool, error) {
		calls++
		if calls < 3 {
			return ModelInvocation{}, false, &pgconn.PgError{Code: "40P01"}
		}
		return ModelInvocation{Key: "same-idempotency-key"}, false, nil
	})
	if err != nil || calls != 3 || result.Key != "same-idempotency-key" {
		t.Fatal("rolled-back reservation did not recover", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, _, err = retryModelReservation(ctx, func() (ModelInvocation, bool, error) {
		calls++
		cancel()
		return ModelInvocation{}, false, &pgconn.PgError{Code: "40P01"}
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled reservation retried", calls, err)
	}
}
