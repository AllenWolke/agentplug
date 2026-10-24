package usagecost

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// The composition authority binds signed execution admission to the conservative
// token estimate and persists enough original execution metadata for background
// recovery. It must not infer a user, session or root from untrusted request IDs.
// ExistingCommand resolves an original durable binding, independent of a live
// browser session. The tree store separately verifies terminal provider proof.
type RunTreeModelBudgetAuthority interface {
	ReserveCommand(context.Context, *sql.Tx, ModelBudgetRequest) (sharedkernel.Scope, RunTreeBudgetCommand, error)
	// Persist the owning invocation's no-send recovery in the SAME transaction.
	// A lost commit acknowledgement must not leave an ownerless budget hold.
	RecordAdmission(context.Context, *sql.Tx, ModelBudgetReservation) error
	ExistingCommand(context.Context, *sql.Tx, ModelBudgetReservation, string, *Event, string, string) (sharedkernel.Scope, RunTreeBudgetCommand, error)
}

// The capability gateway installs its private verified execution estimate only
// for stores requiring it; legacy standalone price-window callers are unchanged.
type ModelBudgetExecutionBindingStore interface {
	RequiresExecutionBinding() bool
}

func (*SQLRunTreeModelBudgetStore) RequiresExecutionBinding() bool { return true }

// SQLRunTreeModelBudgetStore is the atomic adapter used by model billing once
// its real execution/receipt authority is configured. Every operation acquires
// the verified root before the Agent/price window. No provider is called here.
type SQLRunTreeModelBudgetStore struct {
	db        *sql.DB
	tree      *SQLRunTreeBudgetStore
	window    *SQLStore
	authority RunTreeModelBudgetAuthority
	legacy    map[string]ModelBudgetReservation
}

func NewSQLRunTreeModelBudgetStore(db *sql.DB, tree *SQLRunTreeBudgetStore, window *SQLStore, authority RunTreeModelBudgetAuthority, legacyReservationIDs ...string) (*SQLRunTreeModelBudgetStore, error) {
	if db == nil || tree == nil || tree.db != db || tree.authority == nil || tree.audit == nil || window == nil || window.db != db || authority == nil {
		return nil, ErrInvalidUsage
	}
	store := &SQLRunTreeModelBudgetStore{db: db, tree: tree, window: window, authority: authority}
	if err := store.freezeLegacyReservations(legacyReservationIDs); err != nil {
		return nil, err
	}
	return store, nil
}

func treeModelScopeMatches(scope sharedkernel.Scope, budget ModelBudgetScope, runID string) bool {
	return scope.ValidateTrusted() == nil && scope.TenantID == budget.TenantID && scope.DepartmentID == budget.DepartmentID && scope.ApplicationID == budget.ApplicationID && scope.AgentID == budget.AgentID && scope.AgentVersionID == budget.AgentVersionID && scope.RunID == runID
}

func (s *SQLRunTreeModelBudgetStore) Reserve(ctx context.Context, request ModelBudgetRequest) (ModelBudgetReservation, error) {
	if s == nil || s.db == nil {
		return ModelBudgetReservation{}, ErrInvalidUsage
	}
	for _, original := range s.legacy {
		if original.Scope == request.Scope && original.RunID == request.RunID && original.RequestID == request.RequestID {
			return ModelBudgetReservation{}, ErrBudgetReservationClosed
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	scope, command, err := s.authority.ReserveCommand(ctx, tx, request)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if command.Action != "reserve" || command.RequestID != request.RequestID || command.Fingerprint != request.Fingerprint || command.Hold.Micros != request.ReserveMicros || !treeModelScopeMatches(scope, request.Scope, request.RunID) {
		return ModelBudgetReservation{}, ErrBudgetScopeMismatch
	}
	receipt, err := s.tree.ApplyTx(ctx, tx, scope, command)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	// A replay of uncertain/terminal tree accounting cannot admit another send.
	if receipt.Status != "held" || receipt.Exceeded {
		return ModelBudgetReservation{}, ErrBudgetReservationClosed
	}
	if err = s.tree.SaveModelBindingTx(ctx, tx, receipt.rootKey, scope, request, command.Hold.Tokens); err != nil {
		return ModelBudgetReservation{}, err
	}
	reservation, err := s.window.ReserveTx(ctx, tx, request)
	if err != nil {
		return ModelBudgetReservation{}, err
	}
	if reservation.Status != "pending" {
		return ModelBudgetReservation{}, ErrBudgetReservationClosed
	}
	if err = s.tree.SaveModelReservationTx(ctx, tx, reservation); err != nil {
		return ModelBudgetReservation{}, err
	}
	if err = s.authority.RecordAdmission(ctx, tx, reservation); err != nil {
		return ModelBudgetReservation{}, err
	}
	if err = tx.Commit(); err != nil {
		return ModelBudgetReservation{}, err
	}
	return reservation, nil
}

func (s *SQLRunTreeModelBudgetStore) Settle(ctx context.Context, reservation ModelBudgetReservation, event Event, priceVersionID string) (Snapshot, error) {
	var snapshot Snapshot
	var receipt RunTreeBudgetReceipt
	err := s.accountWithReceipt(ctx, reservation, "settle", &event, priceVersionID, "", &receipt, func(tx *sql.Tx) error {
		var err error
		snapshot, err = s.window.SettleTx(ctx, tx, reservation, event, priceVersionID)
		return err
	})
	if err == nil && receipt.Version == "run-tree-budget/v1" {
		snapshot.RunBudget = &receipt
	}
	return snapshot, err
}

func (s *SQLRunTreeModelBudgetStore) Release(ctx context.Context, reservation ModelBudgetReservation) error {
	return s.account(ctx, reservation, "release_unbilled", nil, "", "", func(tx *sql.Tx) error { return s.window.ReleaseTx(ctx, tx, reservation) })
}

func (s *SQLRunTreeModelBudgetStore) MarkReconciliationNeeded(ctx context.Context, reservation ModelBudgetReservation) error {
	return s.account(ctx, reservation, "unknown", nil, "", "", func(tx *sql.Tx) error { return s.window.MarkReconciliationNeededTx(ctx, tx, reservation) })
}

func (s *SQLRunTreeModelBudgetStore) ResolveUncharged(ctx context.Context, reservation ModelBudgetReservation, providerReceipt string) error {
	return s.account(ctx, reservation, "release_unbilled", nil, "", providerReceipt, func(tx *sql.Tx) error { return s.window.ResolveUnchargedTx(ctx, tx, reservation, providerReceipt) })
}

func (s *SQLRunTreeModelBudgetStore) account(ctx context.Context, reservation ModelBudgetReservation, action string, event *Event, priceID, providerReceipt string, windowOperation func(*sql.Tx) error) error {
	return s.accountWithReceipt(ctx, reservation, action, event, priceID, providerReceipt, nil, windowOperation)
}

func (s *SQLRunTreeModelBudgetStore) accountWithReceipt(ctx context.Context, reservation ModelBudgetReservation, action string, event *Event, priceID, providerReceipt string, receipt *RunTreeBudgetReceipt, windowOperation func(*sql.Tx) error) error {
	if s == nil || s.db == nil || windowOperation == nil {
		return ErrInvalidUsage
	}
	if err := validateReservationEnvelope(reservation); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if original, legacy := s.legacy[reservation.ReservationID]; legacy {
		if !sameReservationEnvelope(original, reservation) {
			return ErrBudgetReservationConflict
		}
		return s.accountLegacyTx(ctx, tx, reservation, action, event, priceID, providerReceipt, windowOperation)
	}
	scope, command, err := s.authority.ExistingCommand(ctx, tx, reservation, action, event, priceID, providerReceipt)
	if err != nil {
		return err
	}
	if command.Action != action || command.RequestID != reservation.RequestID || command.Fingerprint != reservation.Fingerprint || command.Hold.Micros != reservation.ReserveMicros || !treeModelScopeMatches(scope, reservation.Scope, reservation.RunID) {
		return ErrBudgetScopeMismatch
	}
	if action == "settle" {
		if event == nil || event.Validate() != nil || !budgetScopeMatchesEvent(reservation, event.Scope) || priceID != reservation.PriceVersionID || command.ActualMicros != event.CostMicros || command.InputTokens != event.InputTokens || command.OutputTokens != event.OutputTokens {
			return ErrBudgetReservationConflict
		}
	} else if event != nil || priceID != "" {
		return ErrInvalidUsage
	}
	settled, err := s.tree.ApplyTx(ctx, tx, scope, command)
	if err != nil {
		return err
	}
	// Even an expiry error rolls back BOTH ledgers; it must never commit one
	// side while losing the original root hold or known provider billing.
	if err = windowOperation(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if receipt != nil {
		*receipt = settled
	}
	return nil
}

var _ ModelBudgetStore = (*SQLRunTreeModelBudgetStore)(nil)
var _ ModelBudgetReconciliationStore = (*SQLRunTreeModelBudgetStore)(nil)
var _ ModelBudgetManualReleaseStore = (*SQLRunTreeModelBudgetStore)(nil)
