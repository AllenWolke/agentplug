package main

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type treeModelBudgetAuthority struct {
	tree   *usagecost.SQLRunTreeBudgetStore
	models *capability.SQLModelInvocationStore
}

func (a treeModelBudgetAuthority) ReserveCommand(ctx context.Context, tx *sql.Tx, request usagecost.ModelBudgetRequest) (sharedkernel.Scope, usagecost.RunTreeBudgetCommand, error) {
	if tx == nil || a.tree == nil || a.models == nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, usagecost.ErrBudgetScopeMismatch
	}
	// The ancestry check runs before ApplyTx. Join it to this reservation
	// transaction and reuse epochs so it does not open a second connection
	// that waits on locks this transaction is about to take.
	ctx = withEpochMemo(withBudgetAncestryTransaction(ctx, tx), tx)
	scope, _, _, tokens, err := capability.ModelBudgetAdmissionAuthority(ctx, request)
	if err != nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, err
	}
	return scope, usagecost.RunTreeBudgetCommand{Action: "reserve", RequestID: request.RequestID, Fingerprint: request.Fingerprint, Hold: usagecost.RunTreeBudgetHold{Micros: request.ReserveMicros, Tokens: tokens}}, nil
}

func (a treeModelBudgetAuthority) ExistingCommand(ctx context.Context, tx *sql.Tx, reservation usagecost.ModelBudgetReservation, action string, event *usagecost.Event, priceID, providerRef string) (sharedkernel.Scope, usagecost.RunTreeBudgetCommand, error) {
	if tx == nil || a.tree == nil || a.models == nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, usagecost.ErrBudgetScopeMismatch
	}
	binding, err := a.tree.ModelBindingTx(ctx, tx, reservation)
	if err != nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, err
	}
	command := usagecost.RunTreeBudgetCommand{Action: action, RequestID: reservation.RequestID, Fingerprint: reservation.Fingerprint, Hold: usagecost.RunTreeBudgetHold{Micros: reservation.ReserveMicros, Tokens: binding.HoldTokens}}
	if action == "unknown" {
		return binding.Scope, command, nil
	}
	evidence, err := a.models.BudgetEvidenceTx(ctx, tx, reservation)
	if err != nil {
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, err
	}
	command.OutcomeFingerprint = evidence.Fingerprint
	switch action {
	case "settle":
		if event == nil || evidence.Event == nil || !usagecost.UsageEventsEqual(*event, *evidence.Event) || priceID != evidence.PriceID {
			return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, usagecost.ErrBudgetReservationConflict
		}
		command.ActualMicros, command.InputTokens, command.OutputTokens = event.CostMicros, event.InputTokens, event.OutputTokens
	case "release_unbilled":
		if evidence.Event != nil || evidence.NoChargeRef == "" || providerRef != "" && providerRef != evidence.NoChargeRef {
			return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, usagecost.ErrBudgetReservationConflict
		}
	default:
		return sharedkernel.Scope{}, usagecost.RunTreeBudgetCommand{}, usagecost.ErrInvalidUsage
	}
	return binding.Scope, command, nil
}

func (a treeModelBudgetAuthority) VerifyOutcome(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, command usagecost.RunTreeBudgetCommand) error {
	if a.tree == nil || a.models == nil || tx == nil {
		return usagecost.ErrBudgetReservationConflict
	}
	reservation, err := a.tree.ModelReservationTx(ctx, tx, scope, command.RequestID)
	if err != nil {
		return err
	}
	binding, err := a.tree.ModelBindingTx(ctx, tx, reservation)
	if err != nil {
		return err
	}
	if command.Fingerprint != reservation.Fingerprint || command.Hold.Micros != reservation.ReserveMicros || command.Hold.Tokens != binding.HoldTokens {
		return usagecost.ErrBudgetReservationConflict
	}
	evidence, err := a.models.BudgetEvidenceTx(ctx, tx, reservation)
	if err != nil {
		return err
	}
	if evidence.Fingerprint != command.OutcomeFingerprint {
		return usagecost.ErrBudgetReservationConflict
	}
	if command.Action == "settle" {
		if evidence.Event == nil || command.ActualMicros != evidence.Event.CostMicros || command.InputTokens != evidence.Event.InputTokens || command.OutputTokens != evidence.Event.OutputTokens {
			return usagecost.ErrBudgetReservationConflict
		}
	} else if command.Action != "release_unbilled" || evidence.Event != nil || evidence.NoChargeRef == "" || command.ActualMicros != 0 || command.InputTokens != 0 || command.OutputTokens != 0 {
		return usagecost.ErrBudgetReservationConflict
	}
	return nil
}

var _ usagecost.RunTreeModelBudgetAuthority = treeModelBudgetAuthority{}

// Legacy accounting reads the original provider evidence, without inventing
// an execution identity/root hold or authorizing a new model request.
func (a treeModelBudgetAuthority) VerifyLegacyAccountingTx(ctx context.Context, tx *sql.Tx, reservation usagecost.ModelBudgetReservation, action string, event *usagecost.Event, priceID, providerRef string) error {
	if tx == nil || a.models == nil {
		return usagecost.ErrBudgetReservationConflict
	}
	evidence, err := a.models.BudgetEvidenceTx(ctx, tx, reservation)
	if err != nil {
		return err
	}
	switch action {
	case "unknown":
		if event != nil || priceID != "" || providerRef != "" {
			return usagecost.ErrInvalidUsage
		}
	case "settle":
		if event == nil || evidence.Event == nil || !usagecost.UsageEventsEqual(*event, *evidence.Event) || priceID != evidence.PriceID || providerRef != "" {
			return usagecost.ErrBudgetReservationConflict
		}
	case "release_unbilled":
		if event != nil || priceID != "" || evidence.Event != nil || evidence.NoChargeRef == "" || providerRef != "" && providerRef != evidence.NoChargeRef {
			return usagecost.ErrBudgetReservationConflict
		}
	default:
		return usagecost.ErrInvalidUsage
	}
	return nil
}

var _ usagecost.LegacyModelAccountingAuthority = treeModelBudgetAuthority{}
