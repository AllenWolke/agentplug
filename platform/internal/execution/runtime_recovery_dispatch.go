package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type recoveryStopReferenceReader interface {
	CurrentRecoveryStopReference(context.Context, platformruntime.Run) (*RecoveryStopReference, error)
}

type runtimeRecoveryCommand struct {
	Version           string                   `json:"version"`
	OriginOperation   string                   `json:"origin_operation"`
	Reference         *RecoveryStopReference   `json:"reference"`
	ConfirmationToken string                   `json:"confirmation_token,omitempty"`
	GroupResume       *AgentGroupWaitReference `json:"group_resume,omitempty"`
	BusinessReview    *CommittedBusinessReview `json:"business_review,omitempty"`
}

// prepareRecoveryDispatch consumes only committed stop provenance. The original
// request and approval reference stay in the Run; only this signed transient
// envelope reaches the SDK. All referenced public State heads are read again.
func (d *Dispatcher) prepareRecoveryDispatch(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest) (bool, error) {
	return d.prepareRecoveryDispatchMode(ctx, running, request, false)
}

func (d *Dispatcher) prepareRecoveryRenewal(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest) (bool, error) {
	return d.prepareRecoveryDispatchMode(ctx, running, request, true)
}

func (d *Dispatcher) prepareRecoveryDispatchMode(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest, renewal bool) (bool, error) {
	reader, supported := d.repository.(recoveryStopReferenceReader)
	if !supported {
		return false, nil // compatibility stores do not fabricate recovery facts
	}
	checkpointReader := d.recoveryCheckpoint
	if renewal {
		checkpointReader = d.recoveryCheckpointRenewal
	}
	ref, err := reader.CurrentRecoveryStopReference(ctx, running)
	if err != nil || ref == nil {
		return false, err
	}
	if request == nil || d.signer == nil || d.authorize == nil || checkpointReader == nil ||
		!ref.valid() || len(ref.Checkpoints) == 0 || running.Revision > 1<<33 ||
		ref.ReadyRevision+1 != running.Revision || ref.RunID != running.ID || request.Scope.RunID != running.ID {
		return false, ErrStopEvidenceInvalid
	}
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	if !ok || policy["content_hash"] != ref.PolicyHash {
		return false, ErrStopEvidenceInvalid
	}
	var approved *ApprovedToolResume
	var group *AgentGroupWaitReference
	var businessReview *CommittedBusinessReview
	if len(running.ResumeInputJSON) != 0 {
		var marker struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(running.ResumeInputJSON, &marker) != nil {
			return false, ErrStopEvidenceInvalid
		}
		if marker.Version == "agent-group-resume/v1" {
			var value AgentGroupWaitReference
			if strictStopJSON(running.ResumeInputJSON, &value) != nil || !value.valid(running.ID) || value.WaitingRevision+2 > ref.StoppedRevision {
				return false, ErrStopEvidenceInvalid
			}
			matched := false
			for _, cp := range ref.Checkpoints {
				h := value.Handoff.Checkpoint
				if cp.StateKey == h.StateKey && cp.Revision == h.Revision && cp.SchemaID == h.SchemaID && cp.ContentHash == h.ContentHash && cp.ExecutionRevision == h.ExecutionRevision && cp.ExpiresAt.Equal(h.ExpiresAt) {
					matched = true
				}
			}
			if !matched {
				return false, ErrStopEvidenceInvalid
			}
			group = &value
		} else if marker.Version == "" {
			// A browser business review is distinct from a tool confirmation.
			// Preserve only the committed, actor-bound decision. The SDK recovers
			// its graph checkpoint; this never grants permission to a write tool.
			if ref.Operation != "resume" || committedBusinessReview(running.ResumeInputJSON, running.Scope) == nil ||
				stopHash(running.ResumeInputJSON) != ref.ResumeInputHash {
				return false, ErrStopEvidenceInvalid
			}
			businessReview = committedBusinessReview(running.ResumeInputJSON, running.Scope)
		} else {
			var value ApprovedToolResume
			if strictStopJSON(running.ResumeInputJSON, &value) != nil || !value.valid(running.Scope) {
				return false, ErrStopEvidenceInvalid
			}
			approved = &value
		}
	}
	needsConfirmation := false
	for _, checkpoint := range ref.Checkpoints {
		if !checkpoint.ExpiresAt.After(time.Now().UTC()) {
			return false, ErrStopEvidenceInvalid
		}
		value, err := checkpointReader(ctx, running.Scope, checkpoint)
		if err != nil || value == nil {
			return false, ErrStopEvidenceInvalid
		}
		if approved == nil || checkpoint.SchemaID != "schema://agentplug/harness-loop/v1" {
			continue
		}
		// Inspect only the approved queue's current head. A progressed tool/model
		// phase must recover via its real receipt, never reissue the old approval.
		if value["version"] != "harness-loop/v1" || value["phase"] != "approval_required" {
			continue
		}
		if checkpoint.Revision != approved.Claims.CheckpointRevision || checkpoint.ContentHash != approved.CheckpointHash ||
			checkpoint.ExecutionRevision != approved.Handoff.ExecutionRevision {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > 256<<10 {
			return false, ErrStopEvidenceInvalid
		}
		var state struct {
			Pending []struct {
				Name   string `json:"name"`
				CallID string `json:"call_id"`
			} `json:"pending"`
		}
		if json.Unmarshal(raw, &state) != nil || len(state.Pending) == 0 || len(state.Pending) > 16 {
			return false, ErrStopEvidenceInvalid
		}
		if state.Pending[0].Name == approved.Claims.ToolName && state.Pending[0].CallID == approved.Claims.CallID {
			needsConfirmation = true
		}
	}
	command := runtimeRecoveryCommand{Version: "runtime-recovery/v1", OriginOperation: "invoke", Reference: ref, BusinessReview: businessReview}
	if group != nil {
		command.OriginOperation = group.OriginOperation
		command.GroupResume = group
	}
	if needsConfirmation {
		resolve := d.approvedResume
		if renewal {
			resolve = d.approvedResumeRenewal
		}
		if resolve == nil {
			return false, ErrStopEvidenceInvalid
		}
		resolved, err := resolve(ctx, running.Scope, running.ResumeInputJSON)
		token, valid := resolved["confirmation_token"].(string)
		if err != nil || !valid || token == "" || len(token) > 8192 {
			return false, ErrStopEvidenceInvalid
		}
		command.ConfirmationToken = token
	}
	// Revocation/cancellation may have happened during the bounded State reads.
	if ctx.Err() != nil || d.authorize(ctx, running.Scope) != nil ||
		(d.coordinatedGuard != nil && d.coordinatedGuard(ctx, running.Scope) != nil) {
		return false, ErrStopEvidenceInvalid
	}
	current, err := reader.CurrentRecoveryStopReference(ctx, running)
	if err != nil || current == nil {
		return false, ErrStopEvidenceInvalid
	}
	first, err := json.Marshal(ref)
	second, secondErr := json.Marshal(current)
	if err != nil || secondErr != nil || !bytes.Equal(first, second) {
		return false, ErrStopEvidenceInvalid
	}
	raw, err := json.Marshal(command)
	if err != nil || len(raw) > 128<<10 {
		return false, ErrStopEvidenceInvalid
	}
	var input map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return false, ErrStopEvidenceInvalid
	}
	request.Operation, request.ResumeInput = "resume", input
	return true, nil
}
