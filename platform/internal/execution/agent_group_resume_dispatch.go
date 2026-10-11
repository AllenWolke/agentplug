package execution

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type agentGroupResumeReader interface {
	CurrentAgentGroupResumeReference(context.Context, platformruntime.Run) (*AgentGroupWaitReference, error)
}

func (d *Dispatcher) prepareAgentGroupResume(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest) (bool, error) {
	return d.prepareAgentGroupResumeMode(ctx, running, request, false)
}

func (d *Dispatcher) prepareAgentGroupRenewal(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest) (bool, error) {
	return d.prepareAgentGroupResumeMode(ctx, running, request, true)
}

func (d *Dispatcher) prepareAgentGroupResumeMode(ctx context.Context, running platformruntime.Run, request *contract.ExecuteRequest, renewal bool) (bool, error) {
	reader, ok := d.repository.(agentGroupResumeReader)
	if !ok {
		return false, nil
	}
	checkpointReader := d.recoveryCheckpoint
	if renewal {
		checkpointReader = d.recoveryCheckpointRenewal
	}
	ref, err := reader.CurrentAgentGroupResumeReference(ctx, running)
	if err != nil {
		return false, err
	}
	if ref == nil {
		return false, nil
	}
	if d.signer == nil || d.authorize == nil || checkpointReader == nil || request.Scope.RunID != running.ID || request.Operation != "resume" {
		return false, ErrStopEvidenceInvalid
	}
	for _, cp := range ref.Checkpoints {
		value, err := checkpointReader(ctx, running.Scope, cp)
		if err != nil || value == nil {
			return false, ErrStopEvidenceInvalid
		}
		if cp.StateKey != ref.Handoff.Checkpoint.StateKey {
			continue
		}
		if value["version"] != "agent-group/v1" || value["phase"] != "gather" || value["parent_run_id"] != running.ID || value["group_key"] != ref.Handoff.GroupKey || value["operation_key"] != ref.Handoff.OperationKey || value["input_fingerprint"] != ref.Handoff.InputFingerprint {
			return false, ErrStopEvidenceInvalid
		}
		bindings, ok := value["bindings"].([]any)
		if !ok || len(bindings) != len(ref.Handoff.ChildKeys) {
			return false, ErrStopEvidenceInvalid
		}
		for i, binding := range bindings {
			item, ok := binding.(map[string]any)
			if !ok || item["child_key"] != ref.Handoff.ChildKeys[i] {
				return false, ErrStopEvidenceInvalid
			}
		}
	}
	if ctx.Err() != nil || d.authorize(ctx, running.Scope) != nil || (d.coordinatedGuard != nil && d.coordinatedGuard(ctx, running.Scope) != nil) {
		return false, ErrStopEvidenceInvalid
	}
	current, err := reader.CurrentAgentGroupResumeReference(ctx, running)
	if err != nil || current == nil {
		return false, ErrStopEvidenceInvalid
	}
	raw, err := json.Marshal(ref)
	latest, latestErr := json.Marshal(current)
	if err != nil || latestErr != nil || !bytes.Equal(raw, latest) || len(raw) > 128<<10 {
		return false, ErrStopEvidenceInvalid
	}
	var input map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&input) != nil {
		return false, ErrStopEvidenceInvalid
	}
	request.ResumeInput = input
	return true, nil
}
