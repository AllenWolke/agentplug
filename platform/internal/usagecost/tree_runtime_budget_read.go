package usagecost

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// A current authorized view, not a model receipt field or a new reservation.
// No row is inserted, updated or repaired by this read.
func (s *SQLRunTreeBudgetStore) ReadRuntimeBudgetTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (RunTreeBudgetReceipt, error) {
	empty := RunTreeBudgetReceipt{}
	if s == nil || tx == nil || s.authority == nil || scope.ValidateTrusted() != nil {
		return empty, ErrBudgetScopeMismatch
	}
	var facts RunTreeBudgetFacts
	var err error
	if reader, ok := s.authority.(RunTreeBudgetReadAuthority); ok {
		facts, err = reader.ReadFacts(ctx, tx, scope)
	} else {
		facts, err = s.authority.Facts(ctx, tx, scope, true)
	}
	if err != nil {
		return empty, err
	}
	if !validTreeFacts(facts, scope) {
		return empty, ErrBudgetScopeMismatch
	}
	var rootID, policyHash string
	var counters RunTreeBudgetCounters
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,policy_hash,limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=? FOR SHARE`), treeScopeKey(facts.RootScope)).Scan(&rootID, &policyHash, &counters.LimitMicros, &counters.LimitTokens, &counters.UsedMicros, &counters.UsedTokens, &counters.HeldMicros, &counters.HeldTokens)
	if err != nil {
		return empty, err
	}
	if rootID != facts.RootScope.RunID || policyHash != facts.PolicyHash || counters.LimitMicros != facts.LimitMicros || counters.LimitTokens != facts.LimitTokens || counters.Validate() != nil {
		return empty, ErrBudgetReservationConflict
	}
	return RunTreeBudgetReceipt{Version: "run-tree-budget/v1", RootRunID: rootID, RunID: scope.RunID,
		Counters: counters, Exceeded: counters.UsedMicros+counters.HeldMicros > counters.LimitMicros || counters.UsedTokens+counters.HeldTokens > counters.LimitTokens}, nil
}

func (s *SQLRunTreeModelBudgetStore) ReadRuntimeBudget(ctx context.Context, scope sharedkernel.Scope) (RunTreeBudgetReceipt, error) {
	if s == nil || s.db == nil || s.tree == nil {
		return RunTreeBudgetReceipt{}, ErrBudgetScopeMismatch
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	defer tx.Rollback()
	receipt, err := s.tree.ReadRuntimeBudgetTx(ctx, tx, scope)
	if err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return RunTreeBudgetReceipt{}, err
	}
	return receipt, nil
}
