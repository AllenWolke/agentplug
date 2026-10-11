package capability

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
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
	return store.CheckModelQuiescence(ctx, capabilityScopeHash(harnessContext{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentInstanceID: scope.AgentInstanceID, PrincipalType: scope.PrincipalType, ActorID: scope.PrincipalID, InstallationID: scope.InstallationID, AgentVersionID: scope.AgentVersionID, SessionID: scope.SessionID}))
}

func (s *SQLModelInvocationStore) CheckModelQuiescence(ctx context.Context, scopeHash string) error {
	if s == nil || s.db == nil || len(scopeHash) != 64 {
		return ErrModelInvocationReconciliationNeeded
	}
	var unsettled bool
	// A resolved decision is terminal only with its applied, reservation-bound
	// audit and the matching closed budget. A charged unknown answer stays
	// non-replayable; acknowledging settlement never retries model generation.
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(
 SELECT 1 FROM platform_model_invocation i WHERE i.scope_hash=? AND NOT (
  (i.status IN ('completed','failed') AND i.billing_state IN ('','done')) OR
  (i.billing_state='resolved' AND EXISTS(
   SELECT 1 FROM platform_model_billing_decision d
   JOIN platform_model_budget_reservation b ON b.reservation_id=d.reservation_id
   WHERE d.scope_hash=i.scope_hash AND d.idempotency_key=i.idempotency_key
    AND d.status='applied'
    AND d.reservation_id=i.billing_recovery_json::jsonb->'reservation'->>'reservation_id'
    AND d.decision_json::jsonb=i.billing_recovery_json::jsonb->'decision'
    AND ((i.status='failed' AND d.decision_json::jsonb->>'outcome'='no_charge' AND b.status='released')
      OR (i.status='reconcile' AND d.decision_json::jsonb->>'outcome'='charged' AND b.status='settled'))
  ))
 ))`), scopeHash).Scan(&unsettled)
	if err != nil {
		return err
	}
	if unsettled {
		return ErrModelInvocationReconciliationNeeded
	}
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
			return ErrModelInvocationReconciliationNeeded
		}
	}
	return nil
}

var _ modelQuiescenceStore = (*SQLModelInvocationStore)(nil)
