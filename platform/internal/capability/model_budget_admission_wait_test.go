package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/usagecost"
)

type scriptedBudgetStore struct {
	reserved []usagecost.ModelBudgetRequest
	script   []error
}

func (s *scriptedBudgetStore) Reserve(ctx context.Context, request usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	if err := ctx.Err(); err != nil {
		return usagecost.ModelBudgetReservation{}, err
	}
	s.reserved = append(s.reserved, request)
	if len(s.script) > 0 {
		err := s.script[0]
		s.script = s.script[1:]
		if err != nil {
			return usagecost.ModelBudgetReservation{}, err
		}
	}
	return usagecost.ModelBudgetReservation{ReservationID: "reservation-wait", Status: "pending", RequestID: request.RequestID}, nil
}

func TestBudgetAdmissionLockWaitRetriesWithoutBecomingExceededOrUnavailable(t *testing.T) {
	request := usagecost.ModelBudgetRequest{RequestID: "wait-1"}
	deferred := &scriptedBudgetStore{script: []error{context.DeadlineExceeded, nil}}
	reservation, err := reserveModelBudgetAdmission(context.Background(), deferred, request)
	if err != nil || reservation.ReservationID != "reservation-wait" || len(deferred.reserved) != 2 {
		t.Fatalf("lock wait must retry the same admission: reservation=%s attempts=%d err=%v", reservation.ReservationID, len(deferred.reserved), err)
	}
	exhausted := &scriptedBudgetStore{script: []error{context.DeadlineExceeded, context.DeadlineExceeded, &pgconn.PgError{Code: "55P03"}}}
	if _, err = reserveModelBudgetAdmission(context.Background(), exhausted, request); !budgetAdmissionDeferred(err) || len(exhausted.reserved) != modelBudgetAdmissionAttempts {
		t.Fatalf("exhausted lock wait must stay deferred: attempts=%d err=%v", len(exhausted.reserved), err)
	}
	exceeded := &scriptedBudgetStore{script: []error{usagecost.ErrBudgetExceeded}}
	if _, err = reserveModelBudgetAdmission(context.Background(), exceeded, request); !errors.Is(err, usagecost.ErrBudgetExceeded) || len(exceeded.reserved) != 1 {
		t.Fatalf("budget exceeded must not be retried as a lock wait: attempts=%d err=%v", len(exceeded.reserved), err)
	}
	canceledStatement := &scriptedBudgetStore{script: []error{&pgconn.PgError{Code: "57014"}, nil}}
	if _, err = reserveModelBudgetAdmission(context.Background(), canceledStatement, request); err != nil || len(canceledStatement.reserved) != 2 {
		t.Fatalf("statement cancellation while waiting for a row lock must retry: attempts=%d err=%v", len(canceledStatement.reserved), err)
	}
	unavailable := &scriptedBudgetStore{script: []error{errors.New("ledger connection refused")}}
	if _, err = reserveModelBudgetAdmission(context.Background(), unavailable, request); budgetAdmissionDeferred(err) || errors.Is(err, usagecost.ErrBudgetExceeded) || len(unavailable.reserved) != 1 {
		t.Fatalf("ledger failure must stay a single unavailable result: attempts=%d err=%v", len(unavailable.reserved), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	caller := &scriptedBudgetStore{}
	if _, err = reserveModelBudgetAdmission(canceled, caller, request); !errors.Is(err, context.Canceled) || len(caller.reserved) != 0 {
		t.Fatalf("caller cancellation must not be treated as an ancestor lock wait: attempts=%d err=%v", len(caller.reserved), err)
	}
}
