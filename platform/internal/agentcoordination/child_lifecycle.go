package agentcoordination

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ObservedChildLifecycle struct {
	Scope              sharedkernel.Scope
	Status             string
	Revision           uint64
	RequestFingerprint string
	TerminalVerified   bool
}

type ChildExecutionLifecycleObserver interface {
	ObserveChildLifecycle(context.Context, *sql.Tx, ChildExecutionRead) (ObservedChildLifecycle, error)
}

type ChildLifecycleSync struct {
	Changed           bool
	Terminal          bool
	Status            string
	ExecutionRevision uint64
}

// Explicit forward migration only; startup must never alter constraints/indexes.
func (s *SQLRouteStore) EnsureLifecycleSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	_, err := s.db.ExecContext(ctx, `ALTER TABLE platform_agent_child_reservation DROP CONSTRAINT IF EXISTS platform_agent_child_reservation_status_check;
ALTER TABLE platform_agent_child_reservation ADD CONSTRAINT platform_agent_child_reservation_status_check CHECK(status IN ('reserved','preparing','accepted','running','completed','failed','cancelled','uncertain'));
ALTER TABLE platform_agent_child_reservation DROP CONSTRAINT IF EXISTS platform_agent_child_admitted_binding_check;
ALTER TABLE platform_agent_child_reservation ADD CONSTRAINT platform_agent_child_admitted_binding_check CHECK(status IN ('reserved','preparing') OR (child_run_id IS NOT NULL AND request_fingerprint IS NOT NULL));
CREATE INDEX IF NOT EXISTS platform_agent_child_live_scan ON platform_agent_child_reservation(child_run_id) WHERE child_run_id IS NOT NULL AND status IN ('accepted','running','uncertain');`)
	return err
}

// SyncChildLifecycleTx asks the trusted execution observer for real proof and
// commits coordinator CAS + redacted Audit/Outbox in the caller's transaction.
// It never dispatches, releases a lease/hold, acknowledges output or resumes.
func (s *SQLRouteStore) SyncChildLifecycleTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int) (ChildLifecycleSync, error) {
	empty := ChildLifecycleSync{}
	if s == nil || tx == nil || s.audit == nil {
		return empty, ErrUnavailable
	}
	observer, ok := s.children.(ChildExecutionLifecycleObserver)
	if !ok {
		return empty, ErrUnavailable
	}
	binding, err := s.RecordedChildRoutingFactsTx(ctx, tx, parent, child, depth)
	if err != nil {
		return empty, err
	}
	observed, err := observer.ObserveChildLifecycle(ctx, tx, ChildExecutionRead{Parent: ParentFacts{Scope: parent}, Target: binding.Target, Depth: depth, RunID: child.RunID})
	if err != nil {
		return empty, err
	}
	if observed.Scope != child || observed.Revision == 0 || observed.RequestFingerprint != binding.RequestFingerprint {
		return empty, ErrDenied
	}
	result := ChildLifecycleSync{Status: observed.Status, ExecutionRevision: observed.Revision}
	var wanted string
	switch observed.Status {
	case "completed", "failed", "cancelled":
		if !observed.TerminalVerified {
			return result, nil
		}
		wanted, result.Terminal = observed.Status, true
	case "running":
		wanted = "running"
	case "accepted", "waiting", "cancelling", "recovering":
		return result, nil
	default:
		return empty, ErrConflict
	}
	var key, status string
	var revision uint64
	// An unchanged reservation must not take the exclusive lock. The child
	// admission shares this row, and holding FOR UPDATE across the caller's
	// remaining authorization work makes that share wait out its deadline.
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision FROM platform_agent_child_reservation WHERE parent_key=? AND child_run_id=?`), routeScopeKey(parent), child.RunID).Scan(&key, &status, &revision)
	if err != nil {
		return empty, err
	}
	if status == wanted {
		return result, nil
	}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision FROM platform_agent_child_reservation WHERE parent_key=? AND child_run_id=? FOR UPDATE`), routeScopeKey(parent), child.RunID).Scan(&key, &status, &revision)
	if err != nil {
		return empty, err
	}
	if status == wanted {
		return result, nil
	}
	if status == "completed" || status == "failed" || status == "cancelled" {
		return empty, ErrConflict
	}
	if wanted == "running" && status != "accepted" && status != "running" {
		return result, nil
	}
	if status != "accepted" && status != "running" && status != "uncertain" {
		return empty, ErrConflict
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_agent_child_reservation SET status=?,revision=revision+1 WHERE child_key=? AND child_run_id=? AND status=? AND revision=? AND request_fingerprint=?`), wanted, key, child.RunID, status, revision, observed.RequestFingerprint)
	if err != nil {
		return empty, err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return empty, err
	}
	if count != 1 {
		return empty, ErrConflict
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	event := audit.Event{ID: "child-sync-" + hex.EncodeToString(nonce[:]), TenantID: child.TenantID, DepartmentID: child.DepartmentID, ApplicationID: child.ApplicationID, ActorType: "system", ActorID: "execution.reconciler", TraceID: child.TraceID, AggregateType: "agent_child", AggregateID: child.RunID, Action: "agent.child_lifecycle_synced", Outcome: "success", Summary: fmt.Sprintf("status=%s execution_revision=%d", wanted, observed.Revision)}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return empty, err
	}
	if err := s.audit.RecordTx(tx, event); err != nil {
		return empty, err
	}
	result.Changed = true
	return result, nil
}

type ChildLifecycleCandidate struct {
	ParentRunID string
	ChildRunID  string
	Depth       int
}

// ChildLifecycleCandidates enumerates only this module's admitted bindings.
// Execution facts and stop authority must be read through execution-owned Ports.
// A bounded seek cursor lets the reconciler visit all children, including those
// whose parents are no longer visible to a human or cannot mint capabilities.
func (s *SQLRouteStore) ChildLifecycleCandidates(ctx context.Context, after string, limit int) ([]ChildLifecycleCandidate, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 256 || (after != "" && !identifier(after)) {
		return nil, ErrUnavailable
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT r.parent_run_id,c.child_run_id,r.child_depth FROM platform_agent_child_reservation c JOIN platform_agent_route r ON r.parent_key=c.parent_key AND r.operation_key=c.operation_key WHERE c.child_run_id IS NOT NULL AND c.request_fingerprint IS NOT NULL AND c.status IN ('accepted','running','uncertain') AND c.child_run_id>? ORDER BY c.child_run_id LIMIT ?`), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ChildLifecycleCandidate
	for rows.Next() {
		var candidate ChildLifecycleCandidate
		if err := rows.Scan(&candidate.ParentRunID, &candidate.ChildRunID, &candidate.Depth); err != nil {
			return nil, err
		}
		if !identifier(candidate.ParentRunID) || !identifier(candidate.ChildRunID) || candidate.Depth < 1 || candidate.Depth > 4 {
			return nil, ErrConflict
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}
