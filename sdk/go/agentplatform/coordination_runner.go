package agentplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
)

const AgentGroupStateSchema = "schema://agentplug/agent-group/v1"

type AgentGroupOptions struct {
	Key, OperationKey, TaskType string
}

type agentGroupTarget struct {
	InputSchema  string `json:"input_schema"`
	OutputSchema string `json:"output_schema"`
}

type agentGroupBinding struct {
	ChildKey         string `json:"child_key"`
	InputFingerprint string `json:"input_fingerprint"`
	OutputSchema     string `json:"output_schema"`
}

// AgentGroupPlanInputHash returns the exact deterministic hash RunAgentGroup
// stores for a fixed route plan. It performs no capability calls and does not
// grant permission to route or execute the group.
func AgentGroupPlanInputHash(operationKey, taskType string, inputs []map[string]any) (string, error) {
	if !harnessSkillIdentifier(operationKey) || !harnessSkillIdentifier(taskType) || len(inputs) < 1 || len(inputs) > 16 {
		return "", harnessError("REQUEST_INVALID")
	}
	var frozen []map[string]any
	if groupDecode(inputs, &frozen) != nil {
		return "", harnessError("REQUEST_INVALID")
	}
	for _, input := range frozen {
		raw, err := json.Marshal(input)
		_, reserved := input["policy_snapshot"]
		if input == nil || reserved || err != nil || len(raw) > 65536 {
			return "", harnessError("REQUEST_INVALID")
		}
	}
	bound, err := json.Marshal([]any{operationKey, taskType, frozen})
	if err != nil {
		return "", harnessError("REQUEST_INVALID")
	}
	digest := sha256.Sum256(bound)
	return hex.EncodeToString(digest[:]), nil
}

type agentGroupState struct {
	Version          string              `json:"version"`
	ParentRunID      string              `json:"parent_run_id"`
	GroupKey         string              `json:"group_key"`
	OperationKey     string              `json:"operation_key"`
	InputFingerprint string              `json:"input_fingerprint"`
	InputHash        string              `json:"input_hash"`
	Phase            string              `json:"phase"`
	Ordinal          int                 `json:"ordinal"`
	Targets          []agentGroupTarget  `json:"targets"`
	Bindings         []agentGroupBinding `json:"bindings"`
	ChildKeys        []string            `json:"child_keys"`
}

var agentGroupStateKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func groupDecode(value any, destination any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(destination) != nil {
		return harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	return nil
}

// RunAgentGroup uses run-scoped CAS checkpoints to prepare/admit a fixed plan.
// It reads once when waiting: it never holds a worker in a polling loop. After
// an uncertain admission, recovery reads the original admission snapshot first.
// Only a verified preparing slot may complete that same fenced CAS admission.
// Child outputs remain untrusted and are always read under current permission.
func (c *CapabilityClient) RunAgentGroup(ctx context.Context, inputs []map[string]any, options AgentGroupOptions) (map[string]any, error) {
	groupResume := c.currentAgentGroupResumeBinding()
	if !agentGroupStateKey.MatchString(options.Key) || !harnessSkillIdentifier(options.OperationKey) || !harnessSkillIdentifier(options.TaskType) || len(inputs) < 1 || len(inputs) > 16 {
		return nil, harnessError("REQUEST_INVALID")
	}
	if groupResume != nil && (options.Key != groupResume.groupKey || options.OperationKey != groupResume.operationKey) {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	var frozen []map[string]any
	if groupDecode(inputs, &frozen) != nil {
		return nil, harnessError("REQUEST_INVALID")
	}
	for _, input := range frozen {
		raw, err := json.Marshal(input)
		_, reserved := input["policy_snapshot"]
		if input == nil || reserved || err != nil || len(raw) > 65536 {
			return nil, harnessError("REQUEST_INVALID")
		}
	}
	inputHash, err := AgentGroupPlanInputHash(options.OperationKey, options.TaskType, frozen)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	parentID, _ := c.context["task_id"].(string)
	c.mu.Unlock()
	if parentID == "" {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	s := agentGroupState{
		Version: "agent-group/v1", ParentRunID: parentID, GroupKey: options.Key,
		OperationKey: options.OperationKey, InputFingerprint: c.businessInputFingerprint,
		InputHash: inputHash, Phase: "route", Targets: []agentGroupTarget{},
		Bindings: []agentGroupBinding{}, ChildKeys: []string{},
	}
	if !validHandoffDigest(s.InputFingerprint) {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	loaded, err := c.LoadCheckpoint(ctx, "coordination", options.Key, AgentGroupStateSchema, 0)
	if err != nil {
		return nil, err
	}
	if err := ValidateRuntimeRecoveryCheckpoint(ctx, "coordination", options.Key, AgentGroupStateSchema, loaded); err != nil {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	if err := validateRuntimeRecoveryAgentGroupCheckpoint(ctx, options.Key, loaded); err != nil {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	var revision uint64
	if cp := loaded["checkpoint"]; cp != nil {
		var record struct {
			Revision uint64          `json:"revision"`
			Value    agentGroupState `json:"value"`
		}
		if groupDecode(cp, &record) != nil || record.Revision < 1 || record.Revision > 63 || record.Value.Version != s.Version ||
			record.Value.ParentRunID != parentID || record.Value.GroupKey != options.Key ||
			record.Value.OperationKey != options.OperationKey || record.Value.InputFingerprint != s.InputFingerprint ||
			record.Value.InputHash != s.InputHash {
			return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
		}
		s, revision = record.Value, record.Revision
	}
	if s.Ordinal < 0 || s.Ordinal > len(frozen) || (s.Phase != "route" && len(s.Targets) != len(frozen)) ||
		(s.Phase == "route" && (s.Ordinal != 0 || len(s.Targets) != 0 || len(s.Bindings) != 0 || len(s.ChildKeys) != 0)) {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	expectedBindings := s.Ordinal
	if s.Phase == "admitting" {
		expectedBindings++
	}
	if len(s.Bindings) != expectedBindings || len(s.ChildKeys) != expectedBindings || len(s.Bindings) > len(frozen) ||
		(s.Phase == "gather" && s.Ordinal != len(frozen)) || (s.Phase != "gather" && s.Phase != "route" && s.Ordinal >= len(frozen)) {
		return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
	}
	for ordinal, binding := range s.Bindings {
		if !childReceiptHash(binding.ChildKey) || !childReceiptHash(binding.InputFingerprint) || binding.OutputSchema != s.Targets[ordinal].OutputSchema ||
			s.ChildKeys[ordinal] != binding.ChildKey {
			return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
		}
	}
	if groupResume != nil {
		if revision == 0 || s.Phase != "gather" || s.GroupKey != groupResume.groupKey ||
			s.OperationKey != groupResume.operationKey || s.InputFingerprint != groupResume.inputFingerprint ||
			!reflect.DeepEqual(s.ChildKeys, groupResume.childKeys) || !agentGroupCheckpointMatches(loaded, groupResume.checkpoint) {
			return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
		}
	}
	save := func() error {
		if revision >= 63 {
			return harnessError("AGENT_GROUP_STATE_LIMIT")
		}
		var value map[string]any
		if groupDecode(s, &value) != nil {
			return harnessError("AGENT_GROUP_STATE_REJECTED")
		}
		receipt, err := c.SaveCheckpoint(ctx, "coordination", options.Key, AgentGroupStateSchema, fmt.Sprintf("group-%d", revision+1), revision, value)
		if err != nil {
			return err
		}
		if err := advanceRuntimeRecoveryAgentGroupCheckpoint(ctx, options.Key, revision, value, receipt); err != nil {
			return harnessError("AGENT_GROUP_STATE_REJECTED")
		}
		revision++
		return nil
	}
	if revision == 0 {
		if err := AuthorizeRuntimeRecoveryStart(ctx, "coordination", options.Key, AgentGroupStateSchema, s.InputHash); err != nil {
			return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
		}
		if err := save(); err != nil {
			return nil, err
		}
	}
	for step := 0; step < 36; step++ {
		switch s.Phase {
		case "route":
			planned, err := c.RouteAgents(ctx, options.OperationKey, options.TaskType, len(frozen))
			if err != nil {
				return nil, err
			}
			var plan struct {
				Targets []agentGroupTarget `json:"targets"`
			}
			if groupDecode(planned["route"], &plan) != nil || len(plan.Targets) != len(frozen) {
				return nil, harnessError("AGENT_ROUTE_REJECTED")
			}
			s.Targets, s.Phase = plan.Targets, "prepare"
			if err := save(); err != nil {
				return nil, err
			}
		case "prepare":
			prepared, err := c.PrepareAgentChild(ctx, options.OperationKey, s.Ordinal, s.Targets[s.Ordinal].InputSchema, frozen[s.Ordinal])
			if err != nil {
				return nil, err
			}
			var preparation struct {
				ChildKey         string `json:"child_key"`
				InputFingerprint string `json:"input_fingerprint"`
			}
			if groupDecode(prepared["preparation"], &preparation) != nil {
				return nil, harnessError("AGENT_PREPARATION_REJECTED")
			}
			s.Bindings = append(s.Bindings, agentGroupBinding{preparation.ChildKey, preparation.InputFingerprint, s.Targets[s.Ordinal].OutputSchema})
			s.ChildKeys = append(s.ChildKeys, preparation.ChildKey)
			s.Phase = "admitting"
			// Persist uncertain admission boundary BEFORE sending. A lost save
			// response cannot accidentally cause an admission.
			if err := save(); err != nil {
				return nil, err
			}
			if _, err := c.AdmitAgentChild(ctx, options.OperationKey, s.Ordinal, preparation.ChildKey, preparation.InputFingerprint); err != nil {
				return nil, err
			}
			s.Ordinal++
			s.Phase = "prepare"
			if s.Ordinal == len(frozen) {
				s.Phase = "gather"
			}
			if err := save(); err != nil {
				return nil, err
			}
		case "admitting":
			binding := s.Bindings[s.Ordinal]
			// This branch only occurs on recovery of the persisted boundary.
			snapshot, err := c.ReadAgentAdmissionState(ctx, options.OperationKey, s.Ordinal, binding.ChildKey, binding.InputFingerprint, binding.OutputSchema)
			if err != nil {
				return nil, err
			}
			state, _ := snapshot["admission_state"].(map[string]any)
			if state["status"] == "preparing" {
				if _, err := c.AdmitAgentChild(ctx, options.OperationKey, s.Ordinal, binding.ChildKey, binding.InputFingerprint); err != nil {
					return nil, err
				}
			}
			s.Ordinal++
			s.Phase = "prepare"
			if s.Ordinal == len(frozen) {
				s.Phase = "gather"
			}
			if err := save(); err != nil {
				return nil, err
			}
		case "gather":
			bindings := make([]AgentChildBinding, len(s.Bindings))
			for ordinal, binding := range s.Bindings {
				bindings[ordinal] = AgentChildBinding{binding.ChildKey, binding.OutputSchema}
			}
			// No outputs in checkpoints, no polling write amplification, and
			// no cached completed result that could bypass later revocation.
			if groupResume != nil && !c.allowAgentGroupGather(groupResume) {
				return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
			}
			result, err := c.GatherAgentChildren(ctx, options.OperationKey, bindings)
			if err != nil {
				return nil, err
			}
			group, ok := result["group"].(map[string]any)
			terminal, terminalOK := group["terminal"].(bool)
			if !ok || !terminalOK {
				return nil, harnessError("AGENT_GROUP_REJECTED")
			}
			if terminal {
				if groupResume != nil && (group["status"] != "completed" || group["outputs_complete"] != true || !c.consumeAgentGroupResume(groupResume)) {
					return nil, harnessError("AGENT_GROUP_REJECTED")
				}
				if err := c.CompleteRuntimeRecoveryStep(ctx, "coordination", options.Key, AgentGroupStateSchema); err != nil {
					return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
				}
				return result, nil
			}
			var reference AgentGroupCheckpointReference
			if groupResume != nil {
				// The resume fence permits only the original coordination load and
				// one Gather. Reuse that verified current head to form a new wait
				// receipt; the platform rejects it if the head changed meanwhile.
				reference, err = agentGroupCheckpointReferenceFromLoad(loaded, s)
			} else {
				reference, err = c.loadCurrentAgentGroupCheckpoint(ctx, options.Key, s)
			}
			if err != nil {
				return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
			}
			childKeys := make([]string, len(s.Bindings))
			for index, binding := range s.Bindings {
				childKeys[index] = binding.ChildKey
			}
			return nil, newAgentGroupPause(options.Key, options.OperationKey, reference, childKeys)
		default:
			return nil, harnessError("AGENT_GROUP_STATE_REJECTED")
		}
	}
	return nil, harnessError("AGENT_GROUP_STATE_LIMIT")
}
