package capability

import (
	"context"
	"database/sql"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CaptureAgentGroupWaitTx validates the current run-scoped head and group
// binding inside the caller's execution transaction. Only references leave
// State; no child output, business input or credential is copied into the wait.
func (s *SQLCheckpointStore) CaptureAgentGroupWaitTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt contract.AgentGroupHandoff) ([]contract.RecoveryCheckpointReference, error) {
	if receipt.RunID != scope.RunID || receipt.Checkpoint.SchemaID != "schema://agentplug/agent-group/v1" {
		return nil, ErrStateUnavailable
	}
	_, key, err := stateKeys(scope, "coordination", receipt.GroupKey)
	if err != nil || key != receipt.Checkpoint.StateKey {
		return nil, ErrStateUnavailable
	}
	refs, err := s.CaptureRecoveryCheckpointsTx(ctx, tx, scope, receipt.ExecutionRevision)
	if err != nil {
		return nil, err
	}
	found := false
	for _, ref := range refs {
		cp := receipt.Checkpoint
		if ref.StateKey == cp.StateKey && ref.Revision == cp.Revision && ref.SchemaID == cp.SchemaID &&
			ref.ContentHash == cp.ContentHash && ref.ExecutionRevision == cp.ExecutionRevision && ref.ExpiresAt.Equal(cp.ExpiresAt) {
			found = true
		}
	}
	if !found {
		return nil, ErrStateContinuityLost
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT value_json FROM platform_business_checkpoint WHERE scope_key=? AND revision=? FOR SHARE`), key, receipt.Checkpoint.Revision).Scan(&raw); err != nil {
		return nil, err
	}
	var value map[string]any
	if decodeStateValue(raw, &value) != nil || value["version"] != "agent-group/v1" || value["phase"] != "gather" ||
		value["parent_run_id"] != scope.RunID || value["group_key"] != receipt.GroupKey ||
		value["operation_key"] != receipt.OperationKey || value["input_fingerprint"] != receipt.InputFingerprint {
		return nil, ErrStateUnavailable
	}
	bindings, ok := value["bindings"].([]any)
	if !ok || len(bindings) != len(receipt.ChildKeys) {
		return nil, ErrStateUnavailable
	}
	for i, binding := range bindings {
		item, ok := binding.(map[string]any)
		if !ok || item["child_key"] != receipt.ChildKeys[i] {
			return nil, ErrStateUnavailable
		}
	}
	return refs, nil
}
