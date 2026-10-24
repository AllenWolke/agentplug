package capability

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

const modelBudgetAdmissionAttempts = 3
const modelBudgetAdmissionWait = 4 * time.Second
const modelBudgetAdmissionStagger = 50 * time.Millisecond

// A lock wait is not a missing ledger and is not a spent budget. The waiting
// parent can hold its row while this child is still the caller's work. Retry
// the same admission; keep the share lock and the exceeded result. A concurrent
// root/window reservation conflict is the same class of transient: it is a
// retriable serialization outcome, not a permanent ledger failure. A permanent
// conflict still fails after the bounded attempts without a new reservation.
func reserveModelBudgetAdmission(ctx context.Context, store interface {
	Reserve(context.Context, usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error)
}, request usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	var last error
	for attempt := 0; attempt < modelBudgetAdmissionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return usagecost.ModelBudgetReservation{}, err
		}
		waitCtx, cancel := context.WithTimeout(ctx, modelBudgetAdmissionWait+time.Duration(attempt)*modelBudgetAdmissionStagger)
		reservation, err := store.Reserve(waitCtx, request)
		// database/sql can return ErrTxDone after its deadline rollback wins a
		// race, and authority adapters may wrap that error. Capture the actual
		// attempt context BEFORE cancel; never infer timeout from ErrTxDone alone.
		// A successful commit remains successful even at the deadline boundary.
		if err != nil && waitCtx.Err() != nil {
			err = waitCtx.Err()
		}
		cancel()
		if err == nil || !budgetAdmissionDeferred(err) {
			return reservation, err
		}
		last = err
		log.Printf("model budget admission deferred error_type=%s", budgetAdmissionErrorType(err))
	}
	return usagecost.ModelBudgetReservation{}, last
}

func budgetAdmissionDeferred(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, usagecost.ErrBudgetReservationConflict) {
		return true
	}
	if sqlutil.IsTransactionRollback(err) {
		return true
	}
	switch sqlutil.SQLState(err) {
	case "55P03", "57014":
		return true
	}
	return false
}

func budgetAdmissionErrorType(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "context_cancelled"
	case errors.Is(err, usagecost.ErrBudgetReservationConflict):
		return "reservation_conflict"
	}
	switch sqlutil.SQLState(err) {
	case "55P03":
		return "sqlstate_55P03"
	case "57014":
		return "sqlstate_57014"
	case "40001":
		return "sqlstate_40001"
	case "40P01":
		return "sqlstate_40P01"
	}
	return "database_unclassified"
}
