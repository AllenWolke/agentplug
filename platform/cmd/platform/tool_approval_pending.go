package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var pendingHarnessKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var pendingToolIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)

type pendingToolApprovalKey struct{}
type pendingToolApprovalBinding struct {
	Scope                                         sharedkernel.Scope
	Key                                           string
	Checkpoint                                    capability.Checkpoint
	RunRevision                                   uint64
	Waiting, Historical                           bool
	ToolName, CallID, Fingerprint, MemoryPolicyID string
}

// ResolvePending reloads governed arguments from a run-owned checkpoint.
// A browser reference cannot replace the head, payload, tool or call ID.
func (a toolApprovalAdapter) ResolvePending(r *http.Request, reference capability.ToolApprovalOperation, action string) (capability.ToolApprovalOperation, error) {
	deny := capability.ErrToolApprovalDenied
	if a.checkpoints == nil || a.runs == nil || a.identity == nil || reference.Payload != nil || !pendingHarnessKey.MatchString(reference.PendingKey) {
		return capability.ToolApprovalOperation{}, deny
	}
	revision, err := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	if err != nil || revision == 0 {
		return capability.ToolApprovalOperation{}, deny
	}
	binding := toolApprovalBrowserBinding{Actor: sharedkernel.Scope{
		PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"),
		TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"),
	}, Session: r.Header.Get("X-Authentication-Session"), Revision: revision}
	ctx := r.Context()
	if err := a.checkSession(ctx, binding); err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	run, err := a.runs.ResolveToolApprovalRun(ctx, binding.Actor, reference.RunID)
	if err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	historical := action == "revoke"
	// Revoke may address an earlier approved checkpoint. Preview/approve and
	// pending reads require the exact head of the currently waiting generation.
	if err != nil || (!historical && !run.Waiting) || reference.CheckpointRevision > 64 {
		return capability.ToolApprovalOperation{}, deny
	}
	if strings.HasSuffix(r.URL.Path, "/pending") {
		if reference.CheckpointRevision != 0 || reference.Name != "" || reference.CallID != "" {
			return capability.ToolApprovalOperation{}, deny
		}
	} else if reference.CheckpointRevision == 0 || !pendingToolIdentifier.MatchString(reference.Name) || !pendingToolIdentifier.MatchString(reference.CallID) {
		return capability.ToolApprovalOperation{}, deny
	}
	checkRead := func() error {
		if err := a.checkSession(ctx, binding); err != nil {
			return errors.Join(deny, err)
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(deny, err)
		}
		// Keep the same public memory policy and dual-identity boundary used by
		// /internal/state/checkpoint; history access alone cannot reveal state.
		for _, access := range []capability.CapabilityResourceAccess{
			{Action: "history.read", ResourceType: "agent_installation", ResourceID: run.Scope.InstallationID},
			{Action: "memory.read", ResourceType: "memory", ResourceID: run.PolicyIDs["memory_policy_id"]},
		} {
			if access.ResourceID == "" {
				return deny
			}
			if err := a.resources.AuthorizeCapabilityResource(ctx, run.Scope, access); err != nil {
				return errors.Join(deny, err)
			}
		}
		return ctx.Err()
	}
	if err := checkRead(); err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	loadRevision := uint64(0)
	if historical {
		loadRevision = reference.CheckpointRevision
	}
	checkpoint, found, err := a.checkpoints.Load(ctx, run.Scope, "harness", reference.PendingKey, "schema://agentplug/harness-loop/v1", loadRevision)
	if err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	if err != nil || !found || checkpoint.ExecutionRevision == 0 || checkpoint.ExecutionRevision > run.Revision ||
		(!historical && (run.Revision < 2 || checkpoint.ExecutionRevision != run.Revision-1)) ||
		(reference.CheckpointRevision != 0 && reference.CheckpointRevision != checkpoint.Revision) {
		return capability.ToolApprovalOperation{}, deny
	}
	encoded, err := json.Marshal(checkpoint.Value)
	if err != nil || len(encoded) > 256<<10 {
		return capability.ToolApprovalOperation{}, deny
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
		return capability.ToolApprovalOperation{}, deny
	}
	operation := state.Pending[0]
	if !pendingToolIdentifier.MatchString(operation.Name) || !pendingToolIdentifier.MatchString(operation.CallID) || !pendingToolIdentifier.MatchString(operation.ModelCallID) || operation.Payload == nil ||
		(operation.RunID != "" && operation.RunID != reference.RunID) ||
		(reference.Name != "" && reference.Name != operation.Name) || (reference.CallID != "" && reference.CallID != operation.CallID) {
		return capability.ToolApprovalOperation{}, deny
	}
	resolved := capability.ToolApprovalOperation{RunID: reference.RunID, Name: operation.Name, CallID: operation.CallID,
		Payload: operation.Payload, PendingKey: reference.PendingKey, CheckpointRevision: checkpoint.Revision}
	// Reuse tool/schema/current immutable policy authorization before exposing
	// even an opaque operation reference. This sets no approval or Run state.
	if _, _, err = a.resolve(ctx, binding, resolved, !historical); err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	if err := checkRead(); err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	latestRun, err := a.runs.ResolveToolApprovalRun(ctx, binding.Actor, reference.RunID)
	if err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	latest, present, loadErr := a.checkpoints.Load(ctx, run.Scope, "harness", reference.PendingKey, "schema://agentplug/harness-loop/v1", loadRevision)
	if loadErr != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, loadErr)
	}
	if err != nil || loadErr != nil || !present || latestRun.Revision != run.Revision || latestRun.Waiting != run.Waiting ||
		latest.Revision != checkpoint.Revision || latest.ContentHash != checkpoint.ContentHash {
		return capability.ToolApprovalOperation{}, deny
	}
	if err := checkRead(); err != nil {
		return capability.ToolApprovalOperation{}, errors.Join(deny, err)
	}
	fingerprint, err := capability.ToolCommandFingerprint(resolved.Name, resolved.Payload)
	if err != nil {
		return capability.ToolApprovalOperation{}, deny
	}
	checkpoint.Value = nil // Only private identifiers and hashes enter the context.
	*r = *r.WithContext(context.WithValue(r.Context(), pendingToolApprovalKey{}, pendingToolApprovalBinding{
		Scope: run.Scope, Key: reference.PendingKey, Checkpoint: checkpoint, RunRevision: run.Revision,
		Waiting: run.Waiting, Historical: historical, ToolName: resolved.Name, CallID: resolved.CallID,
		Fingerprint: fingerprint, MemoryPolicyID: run.PolicyIDs["memory_policy_id"],
	}))
	return resolved, nil
}

// Caller owns IAM continuity before entering: CreateToolStepUp and approval
// proof consumption acquire it first. Run/state locks live through their commit.
func (a toolApprovalAdapter) fencePending(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, name, callID, fingerprint, action string) error {
	bound, present := ctx.Value(pendingToolApprovalKey{}).(pendingToolApprovalBinding)
	if !present {
		return nil // Existing explicitly submitted operation mode remains supported.
	}
	locker, ok := a.checkpoints.(interface {
		LockCheckpointTx(context.Context, *sql.Tx, sharedkernel.Scope, string, string, capability.Checkpoint, bool) error
	})
	if !ok || a.runSQL == nil || tx == nil || bound.Scope != scope || bound.ToolName != name || bound.CallID != callID || bound.Fingerprint != fingerprint || bound.Historical != (action == "tool.approval.revoke") {
		return capability.ErrToolApprovalDenied
	}
	if err := lockBudgetAncestors(ctx, tx, a.runSQL, scope); err != nil {
		return err
	}
	run, err := a.runSQL.BudgetRunTx(ctx, tx, scope.RunID)
	if err != nil {
		return errors.Join(capability.ErrToolApprovalDenied, err)
	}
	if err != nil || run.Scope != scope || run.Revision != bound.RunRevision || (run.Status == platformruntime.StatusWaiting) != bound.Waiting || (!bound.Historical && run.Status != platformruntime.StatusWaiting) {
		return capability.ErrToolApprovalDenied
	}
	if !bound.Historical && scope.ParentRunID != "" {
		if a.waitingAncestry == nil {
			return capability.ErrToolApprovalDenied
		}
		if err := a.waitingAncestry(ctx, tx, scope); err != nil {
			return errors.Join(capability.ErrToolApprovalDenied, err)
		}
	}
	if err := locker.LockCheckpointTx(ctx, tx, scope, "harness", bound.Key, bound.Checkpoint, !bound.Historical); err != nil {
		return err
	}
	for _, access := range []capability.CapabilityResourceAccess{
		{Action: "history.read", ResourceType: "agent_installation", ResourceID: scope.InstallationID},
		{Action: "memory.read", ResourceType: "memory", ResourceID: bound.MemoryPolicyID},
	} {
		if access.ResourceID == "" {
			return capability.ErrToolApprovalDenied
		}
		if err := a.resources.AuthorizeCapabilityResource(ctx, scope, access); err != nil {
			return errors.Join(capability.ErrToolApprovalDenied, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(capability.ErrToolApprovalDenied, err)
	}
	return nil
}
