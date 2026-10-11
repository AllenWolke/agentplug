package usagecost

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CheckChildAdmissionTx pins and locks the verified root allowance before a
// child is accepted. It checks current aggregate headroom without inventing a
// provider charge or double-reserving an entire child. Each cost-bearing model
// call must still reserve through the shared-root model adapter before sending.
// The owning coordinator commits its admission and Audit/Outbox with this row.
func (s *SQLRunTreeBudgetStore) CheckChildAdmissionTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope) error {
	return s.CheckRuntimeAdmissionTx(ctx, tx, parent)
}

// Runtime and child admission use the same authoritative root headroom. A tool
// does not reserve fictional tokens or cost; it must stop when the real model
// ledger has exhausted the run allowance. Known receipts remain readable.
func (s *SQLRunTreeBudgetStore) CheckRuntimeAdmissionTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope) error {
	if s == nil || tx == nil || s.authority == nil || s.audit == nil || parent.ValidateTrusted() != nil {
		return ErrBudgetScopeMismatch
	}
	facts, err := s.authority.Facts(ctx, tx, parent, true)
	if err != nil {
		return err
	}
	if !validTreeFacts(facts, parent) {
		return ErrBudgetScopeMismatch
	}
	key := treeScopeKey(facts.RootScope)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_run_tree_budget(root_key,root_run_id,policy_hash,limit_micros,limit_tokens) VALUES(?,?,?,?,?) ON CONFLICT(root_key) DO NOTHING`), key, facts.RootScope.RunID, facts.PolicyHash, facts.LimitMicros, facts.LimitTokens)
	if err != nil {
		return err
	}
	var counters RunTreeBudgetCounters
	var runID, policyHash string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,policy_hash,limit_micros,limit_tokens,used_micros,used_tokens,held_micros,held_tokens FROM platform_run_tree_budget WHERE root_key=? FOR UPDATE`), key).Scan(&runID, &policyHash, &counters.LimitMicros, &counters.LimitTokens, &counters.UsedMicros, &counters.UsedTokens, &counters.HeldMicros, &counters.HeldTokens)
	if err != nil {
		return err
	}
	if runID != facts.RootScope.RunID || policyHash != facts.PolicyHash || counters.LimitMicros != facts.LimitMicros || counters.LimitTokens != facts.LimitTokens || counters.Validate() != nil {
		return ErrBudgetReservationConflict
	}
	if _, err = ReserveRunTreeBudget(counters, RunTreeBudgetHold{}); err != nil {
		return err
	}
	if counters.UsedTokens+counters.HeldTokens >= counters.LimitTokens {
		return ErrBudgetExceeded
	}
	// A zero-cost allowance still permits genuinely free model calls. Any
	// nonzero-priced call is denied by its exact subsequent model reservation.
	if counters.LimitMicros > 0 && counters.UsedMicros+counters.HeldMicros >= counters.LimitMicros {
		return ErrBudgetExceeded
	}
	return nil
}
