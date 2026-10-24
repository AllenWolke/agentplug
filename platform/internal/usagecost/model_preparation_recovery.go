package usagecost

import (
	"context"
	"database/sql"
	"time"
)

// ModelPreparationBindingReader exposes only the original budget identity and
// uniqueness proof needed to repair a durable, confirmed pre-send failure.
// The invocation owner supplies the transaction; no method commits it or
// grants permission to send, refund or release a reservation.
type ModelPreparationBindingReader interface {
	ModelBindingTx(context.Context, *sql.Tx, ModelBudgetReservation) (RunTreeModelBinding, error)
	UniqueFailedPreparationAdmissionTx(context.Context, *sql.Tx, ModelBudgetReservation, time.Time, time.Time) (bool, error)
}

// ModelPreparationReconciliationWriter retains the full hold and marks it for
// the existing audited decision worker. It participates in, never completes,
// the invocation owner's transaction. Settlement remains a separate port.
type ModelPreparationReconciliationWriter interface {
	MarkReconciliationNeededTx(context.Context, *sql.Tx, ModelBudgetReservation) error
}
