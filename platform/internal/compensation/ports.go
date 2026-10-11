package compensation

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// EffectRegistry admits and fences only registered effects. Owner modules
// share their existing transaction; this port exposes no arbitrary SQL.
type EffectRegistry interface {
	RegisterTx(context.Context, *sql.Tx, Step) error
	GuardRegisteredStopTx(context.Context, *sql.Tx, Step) error
	GuardLeaseTx(context.Context, *sql.Tx, Lease) error
	ReadEffectReferenceTx(context.Context, *sql.Tx, string, string) (Step, error)
}

// Coordinator is the execution-facing cancellation protocol. The storage
// implementation and schema checks remain owned by the compensation module.
type Coordinator interface {
	EffectRegistry
	Queue
	WorkerStore
	BeginTx(context.Context, *sql.Tx, sharedkernel.Scope, uint64) (string, error)
	ConfirmStoppedTx(context.Context, *sql.Tx, sharedkernel.Scope, StopProof) error
	FinalizeTx(context.Context, *sql.Tx, sharedkernel.Scope) error
	Progress(context.Context, sharedkernel.Scope) (Progress, bool, error)
	ProgressTx(context.Context, *sql.Tx, sharedkernel.Scope) (Progress, bool, error)
	CompletionProofTx(context.Context, *sql.Tx, sharedkernel.Scope) (StopProof, error)
	RecordedEffectsTx(context.Context, *sql.Tx, sharedkernel.Scope) ([]Step, error)
	EnrollStoppedTreeTx(context.Context, *sql.Tx, sharedkernel.Scope, []sharedkernel.Scope) error
	VerifyStoppedTreeCoverageTx(context.Context, *sql.Tx, sharedkernel.Scope, []sharedkernel.Scope) error
	EnrollRecordedTx(context.Context, *sql.Tx, sharedkernel.Scope, string) error
}

// LocalEffectRecorder lets an owner record its before-image and provide its
// inverse. It cannot read another owner's state or execute arbitrary SQL.
type LocalEffectRecorder interface {
	AppliedTx(context.Context, *sql.Tx, Step) (bool, error)
	RecordTx(context.Context, *sql.Tx, Step, LocalEffect) error
	Port(string, string, LocalEffectOwner) (Port, error)
}

// OpenCoordinator checks immutable migration markers before exposing the
// protocol. Runtime startup never creates or repairs schema.
func OpenCoordinator(ctx context.Context, db *sql.DB, authority Authority) (Coordinator, error) {
	if ctx == nil || db == nil || authority == nil {
		return nil, ErrInvalid
	}
	if err := CheckSchema(ctx, db); err != nil {
		return nil, err
	}
	if err := CheckEnrollmentSchema(ctx, db); err != nil {
		return nil, err
	}
	return NewSQLStore(db, authority)
}

var _ Coordinator = (*SQLStore)(nil)
var _ LocalEffectRecorder = (*LocalEffectLedger)(nil)
