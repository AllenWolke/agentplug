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
const modelBudgetAdmissionWait = 2 * time.Second

// A 2s ancestor lock wait is not a missing ledger and is not a spent budget.
// The waiting parent can hold its row while this child is still the caller's
// work. Retry the same admission; keep the share lock and the exceeded result.
func reserveModelBudgetAdmission(ctx context.Context, store interface {
	Reserve(context.Context, usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error)
}, request usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	var last error
	for attempt := 0; attempt < modelBudgetAdmissionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return usagecost.ModelBudgetReservation{}, err
		}
		waitCtx, cancel := context.WithTimeout(ctx, modelBudgetAdmissionWait)
		reservation, err := store.Reserve(waitCtx, request)
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
	}
	if sqlutil.SQLState(err) == "55P03" {
		return "sqlstate_55P03"
	}
	return "database_unclassified"
}
