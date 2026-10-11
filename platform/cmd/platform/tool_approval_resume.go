package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Resume owns only the original waiting generation. The browser supplies no
// token, tool arguments, trusted scope or execution lease to this endpoint.
func (a toolApprovalAdapter) Resume(r *http.Request, scope sharedkernel.Scope, operation capability.ToolApprovalOperation, claims capability.ToolConfirmationClaims, store *capability.SQLToolApprovalStore) (any, error) {
	ctx := r.Context()
	bound, present := ctx.Value(pendingToolApprovalKey{}).(pendingToolApprovalBinding)
	browser, authenticated := ctx.Value(toolApprovalBrowserKey{}).(toolApprovalBrowserBinding)
	if !present || !authenticated || store == nil || a.runSQL == nil || bound.Historical || !bound.Waiting || bound.Scope != scope || bound.Key != claims.PendingKey || bound.Checkpoint.Revision != claims.CheckpointRevision {
		return nil, capability.ErrToolApprovalDenied
	}
	// Convert between module-owned DTOs using their fixed, token-free schema.
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, capability.ErrToolApprovalDenied
	}
	var reference execution.ApprovedToolResume
	reference.Version = "harness-tool-resume/v1"
	reference.WaitingRevision = bound.RunRevision
	reference.CheckpointHash = bound.Checkpoint.ContentHash
	if json.Unmarshal(body, &reference.Claims) != nil {
		return nil, capability.ErrToolApprovalDenied
	}
	var revision uint64
	err = store.ResumeApproved(ctx, scope, claims,
		func(ctx context.Context, tx *sql.Tx) error {
			if a.identity.AcquirePermissionReadContinuity(ctx, tx) != nil || lockBudgetAncestors(ctx, tx, a.runSQL, scope) != nil {
				return capability.ErrToolApprovalDenied
			}
			// UPDATE first: never upgrade a shared target Run fence.
			facts, err := a.runSQL.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
			if err != nil || facts.Scope != scope || facts.Revision != bound.RunRevision {
				return capability.ErrToolApprovalDenied
			}
			if a.fencePending(ctx, tx, scope, claims.ToolName, claims.CallID, claims.Fingerprint, "tool.approval.resume") != nil {
				return capability.ErrToolApprovalDenied
			}
			actual, policy, err := a.resolve(ctx, browser, operation, true)
			if err != nil || actual != scope || policy != claims.PolicyHash {
				return capability.ErrToolApprovalDenied
			}
			return nil
		},
		func(ctx context.Context, tx *sql.Tx) error {
			var err error
			revision, err = a.runSQL.PrepareApprovedResumeTx(ctx, tx, scope, bound.RunRevision, reference)
			return err
		})
	if err != nil {
		return nil, err
	}
	// Durable pending discovery, rather than an in-memory queue, owns delivery.
	return map[string]any{"run_id": scope.RunID, "revision": revision, "resume_requested": true, "approval_id": claims.ApprovalID, "replayed": false}, nil
}

// Replay is a read of the already committed command, never another CAS,
// enqueue or signature. Old approval expiry/revocation cannot undo history.
func (a toolApprovalAdapter) ResumeReplay(r *http.Request, operation capability.ToolApprovalOperation, claims capability.ToolConfirmationClaims) (any, bool, error) {
	if a.runSQL == nil {
		return nil, false, capability.ErrToolApprovalDenied
	}
	scope, _, err := a.Resolve(r, operation)
	if err != nil {
		return nil, false, capability.ErrToolApprovalDenied
	}
	run, err := a.runSQL.GetContext(r.Context(), scope.RunID)
	if err != nil || run.Scope != scope {
		return nil, false, capability.ErrToolApprovalDenied
	}
	if len(run.ResumeInputJSON) == 0 {
		return nil, false, nil
	}
	var persisted execution.ApprovedToolResume
	decoder := json.NewDecoder(bytes.NewReader(run.ResumeInputJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&persisted) != nil || decoder.Decode(new(any)) != io.EOF || persisted.Version != "harness-tool-resume/v1" {
		return nil, false, nil
	}
	wanted := execution.ApprovedToolResume{Version: "harness-tool-resume/v1", WaitingRevision: persisted.WaitingRevision, Handoff: persisted.Handoff, CheckpointHash: persisted.CheckpointHash}
	body, err := json.Marshal(claims)
	if err != nil || json.Unmarshal(body, &wanted.Claims) != nil || wanted != persisted || persisted.WaitingRevision < 2 || persisted.WaitingRevision >= 1<<63-1 || operation.Payload != nil || operation.PendingKey != claims.PendingKey || operation.CheckpointRevision != claims.CheckpointRevision || operation.Name != claims.ToolName || operation.CallID != claims.CallID {
		return nil, false, nil
	}
	if run.Revision < persisted.WaitingRevision+1 {
		return nil, false, capability.ErrToolApprovalDenied
	}
	if a.resources.AuthorizeCapabilityResource(r.Context(), scope, capability.CapabilityResourceAccess{Action: "history.read", ResourceType: "agent_installation", ResourceID: scope.InstallationID}) != nil || r.Context().Err() != nil {
		return nil, false, capability.ErrToolApprovalDenied
	}
	return map[string]any{"run_id": scope.RunID, "revision": persisted.WaitingRevision + 1, "resume_requested": true, "approval_id": claims.ApprovalID, "replayed": true}, true, nil
}

func (a toolApprovalAdapter) resolveApprovedDispatch(ctx context.Context, scope sharedkernel.Scope, raw json.RawMessage, signer *capability.ToolApprovalSigner) (map[string]any, error) {
	return a.resolveApprovedResume(ctx, scope, raw, signer, false)
}

// resolveApprovedRenewal rechecks the immutable checkpoint referenced by the
// committed approval. The active Harness head may have moved after dispatch;
// renewal still binds to the original signed request and never extends claim
// expiry or bypasses current authorization.
func (a toolApprovalAdapter) resolveApprovedRenewal(ctx context.Context, scope sharedkernel.Scope, raw json.RawMessage, signer *capability.ToolApprovalSigner) (map[string]any, error) {
	return a.resolveApprovedResume(ctx, scope, raw, signer, true)
}

func (a toolApprovalAdapter) resolveApprovedResume(ctx context.Context, scope sharedkernel.Scope, raw json.RawMessage, signer *capability.ToolApprovalSigner, renewal bool) (map[string]any, error) {
	deny := capability.ErrToolApprovalDenied
	if len(raw) == 0 || len(raw) > 8192 || a.checkpoints == nil || a.runs == nil || signer == nil || ctx.Err() != nil {
		return nil, deny
	}
	var reference execution.ApprovedToolResume
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reference) != nil || decoder.Decode(new(any)) != io.EOF || reference.Version != "harness-tool-resume/v1" || reference.WaitingRevision < 2 || reference.WaitingRevision >= 1<<63-2 {
		return nil, deny
	}
	body, err := json.Marshal(reference.Claims)
	if err != nil {
		return nil, deny
	}
	var claims capability.ToolConfirmationClaims
	if json.Unmarshal(body, &claims) != nil || !pendingHarnessKey.MatchString(claims.PendingKey) || claims.CheckpointRevision == 0 || claims.CheckpointRevision > 64 {
		return nil, deny
	}
	if reference.Claims.Version != claims.Version || reference.Claims.ApprovalID != claims.ApprovalID || reference.Claims.ActorID != claims.ActorID ||
		reference.Claims.ScopeHash != claims.ScopeHash || reference.Claims.AuthorizationEpoch != claims.AuthorizationEpoch || reference.Claims.PolicyHash != claims.PolicyHash ||
		reference.Claims.ToolName != claims.ToolName || reference.Claims.CallID != claims.CallID || reference.Claims.Fingerprint != claims.Fingerprint ||
		reference.Claims.IssuedAt != claims.IssuedAt || reference.Claims.ExpiresAt != claims.ExpiresAt || reference.Claims.PendingKey != claims.PendingKey ||
		reference.Claims.CheckpointRevision != claims.CheckpointRevision {
		return nil, deny
	}
	run, err := a.runs.ResolveToolApprovalRun(ctx, scope, scope.RunID)
	if err != nil || run.Scope != scope || !run.Active || run.Waiting {
		return nil, deny
	}
	readAllowed := func() bool {
		for _, access := range []capability.CapabilityResourceAccess{
			{Action: "history.read", ResourceType: "agent_installation", ResourceID: scope.InstallationID},
			{Action: "memory.read", ResourceType: "memory", ResourceID: run.PolicyIDs["memory_policy_id"]},
		} {
			if access.ResourceID == "" || a.resources.AuthorizeCapabilityResource(ctx, scope, access) != nil {
				return false
			}
		}
		return ctx.Err() == nil
	}
	if !readAllowed() {
		return nil, deny
	}
	checkpoint, operation, err := loadApprovedResumeCheckpoint(ctx, a.checkpoints, scope, reference, claims, run, renewal)
	if err != nil {
		return nil, deny
	}
	actual, policy, err := a.resolveExecution(ctx, scope, operation, true)
	if err != nil || actual != scope || policy != claims.PolicyHash || !readAllowed() {
		return nil, deny
	}
	// Dispatch remains pinned to the current approval_required head. Renewal
	// re-reads the exact historical revision instead, while both paths recheck
	// the latest Run and current IAM/resource authority before re-signing.
	readRevision := checkpoint.Revision
	if !renewal {
		readRevision = 0
	}
	latestCheckpoint, present, err := a.checkpoints.Load(ctx, scope, "harness", claims.PendingKey, "schema://agentplug/harness-loop/v1", readRevision)
	latest, runErr := a.runs.ResolveToolApprovalRun(ctx, scope, scope.RunID)
	if err != nil || !present || latestCheckpoint.Revision != checkpoint.Revision || latestCheckpoint.ContentHash != checkpoint.ContentHash ||
		latestCheckpoint.ExecutionRevision != checkpoint.ExecutionRevision || !latestCheckpoint.ExpiresAt.Equal(checkpoint.ExpiresAt) ||
		runErr != nil || latest.Scope != scope || latest.Revision != run.Revision || !latest.Active || latest.Waiting || !readAllowed() {
		return nil, deny
	}
	token, err := signer.ReissueApproved(ctx, scope, claims)
	if err != nil || ctx.Err() != nil {
		return nil, deny
	}
	return map[string]any{"confirmation_token": token, "handoff": reference.Handoff,
		"checkpoint": map[string]any{"namespace": "harness", "key": claims.PendingKey,
			"schema_id": "schema://agentplug/harness-loop/v1", "revision": checkpoint.Revision,
			"content_hash": checkpoint.ContentHash, "execution_revision": checkpoint.ExecutionRevision}}, nil
}

// loadApprovedResumeCheckpoint chooses the checkpoint lineage appropriate to
// the caller: dispatch (revision 0) must still own the current head, while a
// live command renewal must re-read the exact immutable historical revision.
func loadApprovedResumeCheckpoint(ctx context.Context, store capability.CheckpointStore, scope sharedkernel.Scope, reference execution.ApprovedToolResume, claims capability.ToolConfirmationClaims, run execution.ToolApprovalRun, renewal bool) (capability.Checkpoint, capability.ToolApprovalOperation, error) {
	deny := capability.ErrToolApprovalDenied
	if store == nil || ctx.Err() != nil || reference.WaitingRevision < 2 || reference.WaitingRevision >= 1<<63-2 ||
		claims.CheckpointRevision == 0 || claims.CheckpointRevision > 64 || claims.PendingKey == "" ||
		reference.CheckpointHash == "" || run.Scope != scope || !run.Active || run.Waiting || run.Revision < reference.WaitingRevision+2 ||
		reference.Handoff.Version != "sdk-handler-exit/v1" || reference.Handoff.RunID != scope.RunID ||
		reference.Handoff.ExecutionRevision != reference.WaitingRevision-1 || reference.Handoff.HarnessKey != claims.PendingKey ||
		reference.Handoff.ToolName != claims.ToolName || reference.Handoff.CallID != claims.CallID {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	requestedRevision := uint64(0)
	if renewal {
		requestedRevision = claims.CheckpointRevision
	}
	checkpoint, found, err := store.Load(ctx, scope, "harness", claims.PendingKey, "schema://agentplug/harness-loop/v1", requestedRevision)
	if err != nil || !found || checkpoint.Revision != claims.CheckpointRevision || checkpoint.ExecutionRevision != reference.WaitingRevision-1 || checkpoint.ContentHash != reference.CheckpointHash {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	encoded, err := json.Marshal(checkpoint.Value)
	if err != nil || len(encoded) > 256<<10 {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	var state struct {
		Version string `json:"version"`
		Phase   string `json:"phase"`
		Pending []struct {
			Name        string         `json:"name"`
			CallID      string         `json:"call_id"`
			Payload     map[string]any `json:"payload"`
			ModelCallID string         `json:"model_call_id"`
			RunID       string         `json:"run_id"`
		} `json:"pending"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&state) != nil || state.Version != "harness-loop/v1" || state.Phase != "approval_required" || len(state.Pending) == 0 || len(state.Pending) > 16 {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	operation := state.Pending[0]
	if operation.Name != claims.ToolName || operation.CallID != claims.CallID || operation.Payload == nil ||
		!pendingToolIdentifier.MatchString(operation.Name) || !pendingToolIdentifier.MatchString(operation.CallID) ||
		!pendingToolIdentifier.MatchString(operation.ModelCallID) || operation.RunID != "" && operation.RunID != scope.RunID {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	fingerprint, err := capability.ToolCommandFingerprint(operation.Name, operation.Payload)
	if err != nil || fingerprint != claims.Fingerprint {
		return capability.Checkpoint{}, capability.ToolApprovalOperation{}, deny
	}
	return checkpoint, capability.ToolApprovalOperation{RunID: scope.RunID, Name: operation.Name, CallID: operation.CallID, Payload: operation.Payload}, nil
}
