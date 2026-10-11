package execution

import (
	"context"
	"encoding/json"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ToolApprovalRun exposes only the immutable policy identifiers and durable
// attribution, never the Run's input, lease token, credentials or model output.
type ToolApprovalRun struct {
	Scope      sharedkernel.Scope
	PolicyIDs  map[string]string
	PolicyHash string
	Active     bool
	Waiting    bool
	Revision   uint64
}

func (m *Module) ResolveToolApprovalRun(ctx context.Context, actor sharedkernel.Scope, id string) (ToolApprovalRun, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || id == "" {
		return ToolApprovalRun{}, sharedkernel.ErrInvalidScope
	}
	var run platformruntime.Run
	var err error
	if reader, ok := m.store.(interface {
		GetContext(context.Context, string) (platformruntime.Run, error)
	}); ok {
		run, err = reader.GetContext(ctx, id)
	} else {
		run, err = m.store.Get(id)
	}
	if err != nil {
		return ToolApprovalRun{}, errors.New("owned approval run unavailable")
	}
	scope := run.Scope
	if ctx.Err() != nil || scope.ValidateTrusted() != nil || scope.RunID != id || scope.PrincipalType != actor.PrincipalType || scope.PrincipalID != actor.PrincipalID || scope.TenantID != actor.TenantID || scope.DepartmentID != actor.DepartmentID || scope.ApplicationID != actor.ApplicationID {
		return ToolApprovalRun{}, sharedkernel.ErrInvalidScope
	}
	var envelope struct {
		Input struct {
			Policy map[string]json.RawMessage `json:"policy_snapshot"`
		} `json:"input"`
	}
	if json.Unmarshal(run.RequestJSON, &envelope) != nil {
		return ToolApprovalRun{}, errors.New("approval policy unavailable")
	}
	result := ToolApprovalRun{Scope: scope, PolicyIDs: map[string]string{}, Active: run.Status == platformruntime.StatusRunning || run.Status == platformruntime.StatusWaiting, Waiting: run.Status == platformruntime.StatusWaiting, Revision: run.Revision}
	if json.Unmarshal(envelope.Input.Policy["content_hash"], &result.PolicyHash) != nil || len(result.PolicyHash) != 64 {
		return ToolApprovalRun{}, errors.New("approval policy digest unavailable")
	}
	for _, name := range []string{"model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id", "rule_bundle_version", "rule_bundle_checksum"} {
		if value, exists := envelope.Input.Policy[name]; exists {
			var text string
			if json.Unmarshal(value, &text) != nil {
				return ToolApprovalRun{}, errors.New("approval policy identifier invalid")
			}
			result.PolicyIDs[name] = text
		}
	}
	// Materialized execution snapshots carry the immutable rule binding under
	// rule_bundle. Older callers used flat identifiers. Preserve either form,
	// but reject disagreement rather than silently dropping the signed binding.
	if raw, present := envelope.Input.Policy["rule_bundle"]; present {
		var rule struct {
			Version  string `json:"version"`
			Checksum string `json:"checksum"`
		}
		if json.Unmarshal(raw, &rule) != nil || string(raw) == "null" ||
			((rule.Version == "") != (rule.Checksum == "")) {
			return ToolApprovalRun{}, errors.New("approval rule binding invalid")
		}
		for name, value := range map[string]string{"rule_bundle_version": rule.Version, "rule_bundle_checksum": rule.Checksum} {
			if old := result.PolicyIDs[name]; old != "" && value != "" && old != value {
				return ToolApprovalRun{}, errors.New("approval rule binding disagrees")
			}
			if value != "" {
				result.PolicyIDs[name] = value
			}
		}
	}
	return result, nil
}
