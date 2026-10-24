package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type internalStopReceipt struct {
	ExecutionRevision uint64 `json:"execution_revision"`
	LeaseDigest       string `json:"lease_digest"`
}

func internalIndexOwner(run platformruntime.Run, owner sharedkernel.Scope) bool {
	var command contract.ExecuteRequest
	if owner.ValidateTrusted() != nil || run.Scope != owner || run.ID != owner.RunID || run.AgentEndpoint != "" || json.Unmarshal(run.RequestJSON, &command) != nil || command.ProtocolVersion != contract.ProtocolVersion || command.InputSchema != KnowledgeIndexInputSchema || command.ContextToken != "" || command.Scope.DelegationDepth != 0 || (command.Operation != "run" && command.Operation != "invoke") {
		return false
	}
	c := command.Scope
	return owner == (sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.PrincipalID, PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.RunID, ParentRunID: c.ParentRunID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch})
}

// RecordInternalTaskStopped is callable only by the synchronous execution
// owner after its Execute function and model session cleanup have returned.
// Natural lease expiry, user cancellation and billing status are not proof of
// that return. This durable receipt allows later billing reconciliation without
// inventing a stop acknowledgment or reissuing the provider request.
func (s *SQLStore) RecordInternalTaskStopped(ctx context.Context, owner sharedkernel.Scope, token string, revision uint64) error {
	if token == "" || revision == 0 {
		return platformruntime.ErrLeaseConflict
	}
	run, err := s.GetContext(ctx, owner.RunID)
	if err != nil {
		return err
	}
	if !internalIndexOwner(run, owner) {
		return platformruntime.ErrInvalidRequest
	}
	if run.Status == platformruntime.StatusSucceeded || run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockExecutionAdvisory(ctx, tx, owner.RunID, false); err != nil {
		return err
	}
	var status, actualToken string
	var actualRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,revision,lease_token FROM platform_execution_run WHERE run_id=? FOR UPDATE`), owner.RunID).Scan(&status, &actualRevision, &actualToken); err != nil {
		return err
	}
	if actualToken != token || !((status == "running" && actualRevision == revision) || ((status == "cancelling" || status == "recovering") && actualRevision == revision+1)) {
		return platformruntime.ErrLeaseConflict
	}
	digest := sha256.Sum256([]byte(token))
	receipt := internalStopReceipt{ExecutionRevision: revision, LeaseDigest: hex.EncodeToString(digest[:])}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	var present bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type='internal_task_stopped' AND payload::jsonb=?::jsonb)`), owner.RunID, raw).Scan(&present); err != nil {
		return err
	}
	if !present {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,'internal_task_stopped',?,?)`), owner.RunID, raw, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) InternalTaskStopped(ctx context.Context, run platformruntime.Run) (bool, error) {
	if !internalIndexOwner(run, run.Scope) || run.LeaseToken == "" || run.Revision < 2 || (run.Status != platformruntime.StatusCancelling && run.Status != platformruntime.StatusRecovering) {
		return false, platformruntime.ErrLeaseConflict
	}
	digest := sha256.Sum256([]byte(run.LeaseToken))
	raw, _ := json.Marshal(internalStopReceipt{ExecutionRevision: run.Revision - 1, LeaseDigest: hex.EncodeToString(digest[:])})
	var present bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type='internal_task_stopped' AND payload::jsonb=?::jsonb)`), run.ID, raw).Scan(&present)
	return present, err
}

// ListInternalStopping does not reclaim owners. Only the worker's durable
// acknowledgment plus settled model ledger can complete a pending stop.
func (s *SQLStore) ListInternalStopping(ctx context.Context, after string, limit int) ([]string, error) {
	if limit < 1 || limit > 100 {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT run_id FROM platform_execution_run WHERE run_id>? AND agent_endpoint='' AND (status IN ('cancelling','recovering') OR (status='running' AND lease_token<>'' AND (lease_until IS NULL OR lease_until<=clock_timestamp()))) AND CASE WHEN request_json IS JSON OBJECT THEN request_json::jsonb->>'input_schema' ELSE NULL END=? ORDER BY run_id LIMIT ?`), after, KnowledgeIndexInputSchema, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
