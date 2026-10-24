package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type modelQuiescenceStore interface {
	CheckModelQuiescence(context.Context, string) error
}

// CheckTaskModelQuiescence is a system composition port, not a user grant or
// stop acknowledgment. Call it only after the execution owner has exited and
// the execution generation is fenced. The ledger groups by session, so other
// unfinished calls in that same session conservatively block completion too.
func (m *Module) CheckTaskModelQuiescence(ctx context.Context, scope sharedkernel.Scope) error {
	if m == nil || scope.ValidateTrusted() != nil {
		return ErrModelInvocationReconciliationNeeded
	}
	store, ok := m.modelStore.(modelQuiescenceStore)
	if !ok {
		return ErrModelInvocationReconciliationNeeded
	}
	if err := store.CheckModelQuiescence(ctx, modelEvidenceScopeHash(scope)); err != nil {
		m.expediteModelReconciliation(ctx, scope)
		return err
	}
	if err := store.CheckModelQuiescence(ctx, modelSelectionScopeHash(scope)); err != nil {
		// A process can die after persisting a physical result/hold but before
		// recording its route disposition. Recover that CAS transition without
		// a model send, then verify the original budget holds in a new snapshot.
		if recoveryErr := m.recoverStoppedModelRouteDispositions(ctx, scope); recoveryErr == nil {
			if retryErr := store.CheckModelQuiescence(ctx, modelSelectionScopeHash(scope)); retryErr == nil {
				return nil
			}
		}
		m.expediteModelReconciliation(ctx, scope)
		return err
	}
	return nil
}

// expediteModelReconciliation makes the run's in-doubt model calls due for the
// reconciliation worker; the fence's retry then observes the reconciled state.
// It never fabricates a result, so an unconfirmable outcome still fails closed.
func (m *Module) expediteModelReconciliation(ctx context.Context, scope sharedkernel.Scope) {
	store, ok := m.modelStore.(interface {
		ExpediteBillingRecovery(context.Context, string) error
	})
	if !ok {
		return
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := store.ExpediteBillingRecovery(writeCtx, modelEvidenceScopeHash(scope)); err != nil {
		log.Printf("model reconciliation expedite failed: %v", err)
	}
	if err := store.ExpediteBillingRecovery(writeCtx, modelSelectionScopeHash(scope)); err != nil {
		log.Printf("model selection reconciliation expedite failed: %v", err)
	}
}

func (s *SQLModelInvocationStore) CheckModelQuiescence(ctx context.Context, scopeHash string) error {
	if s == nil || s.db == nil || len(scopeHash) != 64 {
		return ErrModelInvocationReconciliationNeeded
	}
	// 保留原来的同快照语义；账务表由其所有者在同一个只读事务内核验。
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.checkModelQuiescenceTx(ctx, tx, scopeHash, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// A cancellation owner is supplied only after the execution generation is
// stopped. Ordinary completion, recovery and group resume pass nil.
func (s *SQLModelInvocationStore) checkModelQuiescenceTx(ctx context.Context, tx *sql.Tx, scopeHash string, cancellationOwner *sharedkernel.Scope) error {
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT i.idempotency_key,i.fingerprint,i.status,i.billing_state,COALESCE(i.billing_recovery_json,''),i.invocation_token,i.response_json IS NOT NULL,
 EXISTS(SELECT 1 FROM platform_model_billing_decision d
  WHERE d.scope_hash=i.scope_hash AND d.idempotency_key=i.idempotency_key AND d.status='applied'
   AND d.reservation_id=i.billing_recovery_json::jsonb->'reservation'->>'reservation_id'
   AND d.decision_json::jsonb=i.billing_recovery_json::jsonb->'decision')
 FROM platform_model_invocation i WHERE i.scope_hash=?
 AND NOT (i.status IN ('completed','failed') AND i.billing_state IN ('','done'))`), scopeHash)
	if err != nil {
		return err
	}
	defer rows.Close()
	var closures []usagecost.ModelBudgetClosure
	type retainedCall struct {
		key, fingerprint string
		recovery         BillingRecovery
	}
	var pending []retainedCall
	var retained []usagecost.ModelBudgetReservation
	for rows.Next() {
		var key, fingerprint, status, billing, raw, token string
		var applied, responseKnown bool
		if err := rows.Scan(&key, &fingerprint, &status, &billing, &raw, &token, &responseKnown, &applied); err != nil {
			return err
		}
		var recovery BillingRecovery
		if len(raw) > 65536 || json.Unmarshal([]byte(raw), &recovery) != nil {
			return ErrModelInvocationReconciliationNeeded
		}
		if status == "reconcile" && billing == "manual" && recovery.Decision == nil {
			if cancellationOwner != nil && !responseKnown && cancellationRetainsUnknown(*cancellationOwner, fingerprint, token, &recovery) {
				retained = append(retained, recovery.Reservation)
				continue
			}
			pending = append(pending, retainedCall{key, fingerprint, recovery})
			continue
		}
		if billing != "resolved" || !applied || recovery.Decision == nil || !validBillingDecision(*recovery.Decision) || recovery.Decision.ReservationID != recovery.Reservation.ReservationID {
			// Classify which retained row blocks the fence; without this the
			// caller only sees a generic "requires reconciliation".
			decisionID := ""
			if recovery.Decision != nil {
				decisionID = recovery.Decision.ID
			}
			log.Printf("model quiescence unconfirmed scope=%s call=%s status=%s billing=%s decision_applied=%v has_decision=%v decision_id=%s reservation=%s",
				scopeHash, key, status, billing, applied, recovery.Decision != nil, decisionID, recovery.Reservation.ReservationID)
			return ErrModelInvocationReconciliationNeeded
		}
		closed := ""
		if status == "failed" && recovery.Decision.Outcome == "no_charge" {
			closed = "released"
		} else if status == "reconcile" && recovery.Decision.Outcome == "charged" {
			closed = "settled"
		} else {
			return ErrModelInvocationReconciliationNeeded
		}
		closures = append(closures, usagecost.ModelBudgetClosure{Reservation: recovery.Reservation, Status: closed})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(pending) > 0 {
		states, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT state_json FROM platform_model_route_execution
 WHERE scope_hash=? AND state_json::jsonb->'steps' @> '[{"disposition":"retained_unknown"}]'::jsonb LIMIT 10001`), scopeHash)
		if err != nil {
			return err
		}
		var executions []ModelRouteExecution
		for states.Next() {
			var raw string
			if err := states.Scan(&raw); err != nil {
				states.Close()
				return err
			}
			state, err := decodeModelRouteExecution(raw)
			if err != nil || len(executions) >= 10000 {
				states.Close()
				return ErrModelInvocationReconciliationNeeded
			}
			executions = append(executions, state)
		}
		err = states.Err()
		states.Close()
		if err != nil {
			return err
		}
		for _, call := range pending {
			matches := 0
			for _, state := range executions {
				if executionRetainsUnknown(state, call.key, call.fingerprint, &call.recovery) {
					matches++
				}
			}
			if matches != 1 {
				return ErrModelInvocationReconciliationNeeded
			}
			retained = append(retained, call.recovery.Reservation)
		}
	}
	if len(retained) > 0 {
		reader, ok := s.budgetClosures.(usagecost.ModelBudgetRetentionReader)
		if !ok {
			return ErrModelInvocationReconciliationNeeded
		}
		confirmed, err := reader.BudgetRetentionsConfirmedTx(ctx, tx, retained)
		if err != nil {
			return err
		}
		if !confirmed {
			return ErrModelInvocationReconciliationNeeded
		}
	}
	if len(closures) > 0 {
		if s.budgetClosures == nil {
			return ErrModelInvocationReconciliationNeeded
		}
		confirmed, err := s.budgetClosures.BudgetClosuresConfirmedTx(ctx, tx, closures)
		if err != nil {
			return err
		}
		if !confirmed {
			return ErrModelInvocationReconciliationNeeded
		}
	}
	return nil
}

// SetModelBudgetClosureReader 仅在启动组合时调用，不能由请求替换账务证明。
func (s *SQLModelInvocationStore) SetModelBudgetClosureReader(reader usagecost.ModelBudgetClosureReader) error {
	if s == nil || reader == nil || s.budgetClosures != nil {
		return ErrModelInvocationConflict
	}
	s.budgetClosures = reader
	return nil
}

func (s *memoryModelInvocationStore) CheckModelQuiescence(ctx context.Context, scopeHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.ScopeHash == scopeHash && r.Status != "completed" && r.Status != "failed" {
			matches := 0
			if r.Status == "reconcile" {
				for key, state := range s.routeExecutions {
					if strings.HasPrefix(key, scopeHash+"\x00") && executionRetainsUnknown(state, r.Key, r.Fingerprint, r.Recovery) {
						matches++
					}
				}
			}
			if matches == 1 {
				continue
			}
			return ErrModelInvocationReconciliationNeeded
		}
	}
	return nil
}

var _ modelQuiescenceStore = (*SQLModelInvocationStore)(nil)
