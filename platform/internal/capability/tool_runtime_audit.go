package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Platform-created metadata only. Never contains input, output, code, credentials
// or confirmation tokens. StartedAt is assigned from the transaction DB clock.
type ToolRuntimeAuditBinding struct {
	Descriptor     RuntimeToolDescriptor `json:"descriptor"`
	PolicyHash     string                `json:"policy_hash"`
	ApprovalDigest string                `json:"approval_digest,omitempty"`
	StartedAt      *time.Time            `json:"started_at,omitempty"`
}

// Called after the fenced ledger transition and before its commit. Reading the
// original recovery query also supports recovery workers without HTTP context.
func (s *SQLToolInvocationStore) recordRuntimeAuditTx(ctx context.Context, tx *sql.Tx,
	l ToolExecutionLease, transition string, result map[string]any) error {
	if s.audit == nil {
		return nil // Low-level fixtures may use a standalone ledger.
	}
	var raw sql.NullString
	var now time.Time
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT recovery_query,updated_at FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_fence=? FOR UPDATE`), l.ScopeHash, l.CallID, l.Fingerprint, l.Fence).Scan(&raw, &now); err != nil {
		return err
	}
	var q ToolReceiptQuery
	if !raw.Valid || len(raw.String) > 65536 || json.Unmarshal([]byte(raw.String), &q) != nil ||
		q.Scope.ValidateTrusted() != nil || ToolReceiptScopeHash(q.Scope) != l.ScopeHash || q.CallID != l.CallID || q.Fingerprint != l.Fingerprint || q.Name == "" {
		return ErrToolInvocationConflict
	}
	// Old receipts can be reconciled without inventing their original policy or
	// timings. All newly admitted calls require the real runtime binding.
	meta := q.RuntimeAudit
	if transition == "executing" {
		if meta == nil || meta.Descriptor.Validate() != nil || !auditRuntimeDigest(meta.PolicyHash) {
			return ErrToolInvocationConflict
		}
		started := now.UTC()
		meta.StartedAt = &started
		encoded, err := json.Marshal(q)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET recovery_query=? WHERE scope_hash=? AND call_id=? AND fingerprint=? AND lease_fence=?`), string(encoded), l.ScopeHash, l.CallID, l.Fingerprint, l.Fence); err != nil {
			return err
		}
	}
	step := sha256.Sum256([]byte(l.ScopeHash + "\x00" + l.CallID))
	metadata := map[string]any{
		"version": "runtime-execution-audit/v1", "run_id": q.Scope.RunID,
		"step_id": fmt.Sprintf("runtime-%x", step), "call_id": l.CallID,
		"tool_name": q.Name, "permission_scope_hash": l.ScopeHash,
		"permission_scope":    nil,
		"authorization_epoch": q.Scope.AuthorizationEpoch, "fingerprint": l.Fingerprint,
		"lease_fence": l.Fence, "status": transition, "execution_type": nil,
		"risk": nil, "policy_snapshot_hash": nil, "approval_digest": nil,
		"started_at": nil, "finished_at": nil, "duration_ms": nil,
		"error_type": nil, "output_size_bytes": nil,
		"resource_usage": map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil},
	}
	if meta != nil {
		if meta.Descriptor.Validate() != nil || !auditRuntimeDigest(meta.PolicyHash) {
			return ErrToolInvocationConflict
		}
		metadata["execution_type"], metadata["risk"] = meta.Descriptor.ExecutionType, meta.Descriptor.Risk
		metadata["permission_scope"] = toolPermissionScope(q.Name)
		metadata["policy_snapshot_hash"] = meta.PolicyHash
		if meta.ApprovalDigest != "" {
			if !auditRuntimeDigest(meta.ApprovalDigest) {
				return ErrToolInvocationConflict
			}
			metadata["approval_digest"] = meta.ApprovalDigest
		}
		metadata["started_at"] = meta.StartedAt
		if transition != "executing" && meta.StartedAt != nil {
			duration := now.Sub(*meta.StartedAt).Milliseconds()
			if duration < 0 {
				return ErrToolInvocationConflict
			}
			metadata["duration_ms"] = duration
		}
	}
	if transition != "executing" {
		metadata["finished_at"] = now.UTC()
	}
	switch transition {
	case "failed", "preparation_expired":
		metadata["error_type"] = "TOOL_NOT_SUBMITTED"
	case "unknown", "execution_expired":
		metadata["error_type"] = "TOOL_RESULT_UNKNOWN"
	}
	if result != nil && result["_runtime_receipt_version"] == observationVersion {
		encoded, err := json.Marshal(result["observation"])
		var observation runtimeObservation
		if err != nil || len(encoded) > 128<<10 || json.Unmarshal(encoded, &observation) != nil ||
			observation.Version != observationVersion || observation.RunID != q.Scope.RunID || observation.CallID != q.CallID || observation.ToolName != q.Name || observation.PermissionScopeHash != l.ScopeHash || !validToolPermissionScope(observation.PermissionScope, q.Name) || observation.OutputBytes < 0 || observation.OutputBytes > observationOutputLimit {
			return ErrToolInvocationConflict
		}
		metadata["output_size_bytes"] = observation.OutputBytes
		// Use an enum, never arbitrary provider error text.
		switch observation.Status {
		case "succeeded", "failed", "unknown", "cancelled", "timeout", "timed_out":
			metadata["observation_status"] = observation.Status
		default:
			metadata["observation_status"] = "unknown"
		}
		metadata["error_type"] = auditRuntimeError(observation.ErrorType)
		metadata["resource_usage"] = auditRuntimeResources(observation.ResourceUsage)
	}
	id := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", l.ScopeHash, l.CallID, l.Fence, transition)))
	if q.RemoteContract != nil {
		identity, identityErr := NewToolOperationIdentity(q)
		if identityErr != nil || q.RemoteContract.Validate() != nil {
			return ErrToolInvocationConflict
		}
		// Separate versioned event: keep the existing closed runtime-step schema
		// intact while committing the remote contract with the ledger transition.
		binding, err := json.Marshal(struct {
			Version  string                `json:"version"`
			Identity ToolOperationIdentity `json:"identity"`
			Contract RemoteToolContract    `json:"contract"`
			Fence    uint64                `json:"attempt_fence"`
			Status   string                `json:"status"`
		}{"remote-tool-contract-audit/v1", identity, *q.RemoteContract, l.Fence, transition})
		if err != nil {
			return err
		}
		if err = s.audit.RecordTx(tx, audit.Event{ID: fmt.Sprintf("tool-contract-%x", id),
			TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID,
			ActorType: q.Scope.PrincipalType, ActorID: q.Scope.PrincipalID, TraceID: q.Scope.TraceID,
			AggregateType: "run", AggregateID: q.Scope.RunID, Action: "runtime.tool.remote_contract",
			Outcome: transition, Summary: string(binding), CreatedAt: now.UTC()}); err != nil {
			return err
		}
	}
	if diagnostic, ok := ctx.Value(toolFailureDiagnosticKey{}).(toolFailureDiagnostic); ok {
		// Keep the closed runtime-step v1 schema unchanged. A separate audit
		// event commits with this exact failed/unknown ledger transition.
		cause, err := json.Marshal(map[string]any{"version": "runtime-tool-failure-cause/v1",
			"run_id": q.Scope.RunID, "step_id": fmt.Sprintf("runtime-%x", step),
			"call_id": l.CallID, "tool_name": q.Name, "tool_outcome": transition,
			"cause_type": diagnostic.causeType, "cause_stage": diagnostic.causeStage})
		if err != nil {
			return err
		}
		if err := s.audit.RecordTx(tx, audit.Event{ID: fmt.Sprintf("tool-failure-%x", id),
			TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID,
			ActorType: q.Scope.PrincipalType, ActorID: q.Scope.PrincipalID, TraceID: q.Scope.TraceID,
			AggregateType: "run", AggregateID: q.Scope.RunID, Action: "runtime.tool.failure_cause",
			Outcome: transition, Summary: string(cause), CreatedAt: now.UTC()}); err != nil {
			return err
		}
	}
	summary, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return s.audit.RecordTx(tx, audit.Event{ID: fmt.Sprintf("runtime-%x", id),
		TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID,
		ActorType: q.Scope.PrincipalType, ActorID: q.Scope.PrincipalID, TraceID: q.Scope.TraceID,
		AggregateType: "run", AggregateID: q.Scope.RunID, Action: "runtime.tool." + transition,
		Outcome: transition, Summary: string(summary), CreatedAt: now.UTC()})
}

func auditRuntimeError(value string) any {
	if value == "" {
		return nil
	}
	switch value {
	case "CODE_EXITED", "OUTPUT_LIMIT", "CANCELLED", "TIME_LIMIT", "RESOURCE_LIMIT", "TOOL_OUTPUT_INVALID":
		return value
	default:
		return "EXECUTOR_ERROR"
	}
}

func auditRuntimeDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func auditRuntimeResources(input map[string]any) map[string]any {
	result := map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil}
	for _, key := range []string{"cpu_time_ms", "peak_memory_bytes", "disk_bytes", "sampled_peak_memory_bytes", "sample_count", "disk_sample_count"} {
		if value, exists := input[key]; exists {
			// json decoding gives float64; only bounded non-negative integers qualify.
			if numeric, ok := value.(float64); ok && numeric >= 0 && numeric < 1<<53 && numeric == float64(int64(numeric)) {
				result[key] = numeric
			}
		}
	}
	if value, ok := input["measurement_complete"].(bool); ok {
		result["measurement_complete"] = value
	}
	switch input["measurement_source"] {
	case "docker_engine_sampled/v1", "unavailable":
		result["measurement_source"] = input["measurement_source"]
	}
	switch input["disk_measurement_source"] {
	case "docker_exec_tmpfs_stat/v1", "unavailable":
		result["disk_measurement_source"] = input["disk_measurement_source"]
	}
	return result
}
