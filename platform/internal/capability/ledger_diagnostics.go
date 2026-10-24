package capability

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Only stable categories reach logs, never SQL text, bound values or payloads.
func logLedgerFailure(stage string, err error) {
	if state := sqlutil.SQLState(err); state != "" {
		log.Printf("capability_ledger_failed stage=%s sqlstate=%s", stage, state)
		return
	}
	log.Printf("capability_ledger_failed stage=%s error_type=%s", stage, ledgerErrorType(err))
}

func ledgerErrorType(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "context_cancelled"
	case errors.Is(err, sql.ErrTxDone):
		return "transaction_done"
	case errors.Is(err, usagecost.ErrBudgetScopeMismatch):
		return "budget_scope_mismatch"
	case errors.Is(err, usagecost.ErrBudgetReservationClosed):
		return "budget_reservation_closed"
	case errors.Is(err, usagecost.ErrBudgetReservationConflict):
		return "budget_reservation_conflict"
	case errors.Is(err, ErrModelInvocationConflict):
		return "model_invocation_conflict"
	default:
		return "unclassified"
	}
}
