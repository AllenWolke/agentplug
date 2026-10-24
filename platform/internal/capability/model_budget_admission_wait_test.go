package capability

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/usagecost"
)

type scriptedBudgetStore struct {
	reserved []usagecost.ModelBudgetRequest
	script   []error
}

type deadlineRollbackBudgetStore struct{ calls int }

func (s *deadlineRollbackBudgetStore) Reserve(ctx context.Context, _ usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	s.calls++
	if s.calls == 1 {
		<-ctx.Done()
		return usagecost.ModelBudgetReservation{}, sql.ErrTxDone
	}
	return usagecost.ModelBudgetReservation{ReservationID: "same-request-after-rollback"}, nil
}

func TestBudgetAdmissionDeadlineRollbackPreservesAttemptContext(t *testing.T) {
	store := &deadlineRollbackBudgetStore{}
	got, err := reserveModelBudgetAdmission(context.Background(), store, usagecost.ModelBudgetRequest{RequestID: "same"})
	if err != nil || store.calls != 2 || got.ReservationID == "" {
		t.Fatalf("deadline rollback must retry admission only: calls=%d err=%v", store.calls, err)
	}
	// ErrTxDone without an expired attempt is not proof of a timeout.
	plain := &scriptedBudgetStore{script: []error{sql.ErrTxDone}}
	if _, err = reserveModelBudgetAdmission(context.Background(), plain, usagecost.ModelBudgetRequest{}); !errors.Is(err, sql.ErrTxDone) || len(plain.reserved) != 1 {
		t.Fatalf("unexplained transaction termination must not be retried: %v", err)
	}
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	stopped := &deadlineRollbackBudgetStore{}
	if _, err = reserveModelBudgetAdmission(parent, stopped, usagecost.ModelBudgetRequest{}); !errors.Is(err, context.DeadlineExceeded) || stopped.calls != 1 {
		t.Fatalf("parent deadline must stop subsequent attempts: calls=%d err=%v", stopped.calls, err)
	}
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
	transientConflict := &scriptedBudgetStore{script: []error{usagecost.ErrBudgetReservationConflict, nil}}
	if _, err = reserveModelBudgetAdmission(context.Background(), transientConflict, request); err != nil || len(transientConflict.reserved) != 2 {
		t.Fatalf("transient reservation conflict must retry the same admission: attempts=%d err=%v", len(transientConflict.reserved), err)
	}
	if budgetAdmissionErrorType(usagecost.ErrBudgetReservationConflict) != "reservation_conflict" {
		t.Fatalf("reservation conflict must be logged distinctly: %s", budgetAdmissionErrorType(usagecost.ErrBudgetReservationConflict))
	}
	exhaustedConflict := &scriptedBudgetStore{script: []error{usagecost.ErrBudgetReservationConflict, usagecost.ErrBudgetReservationConflict, usagecost.ErrBudgetReservationConflict}}
	if _, err = reserveModelBudgetAdmission(context.Background(), exhaustedConflict, request); !errors.Is(err, usagecost.ErrBudgetReservationConflict) || len(exhaustedConflict.reserved) != modelBudgetAdmissionAttempts {
		t.Fatalf("permanent reservation conflict must fail after bounded attempts without duplicating: attempts=%d err=%v", len(exhaustedConflict.reserved), err)
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
