package capability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// CapabilityResourceAccess is derived from the verified route and input.
// The Agent cannot choose an action or supply a different authorization scope.
type CapabilityResourceAccess struct{ Action, ResourceType, ResourceID string }
type CapabilityResourceAuthority interface {
	AuthorizeCapabilityResource(context.Context, sharedkernel.Scope, CapabilityResourceAccess) error
}

func resourceAccessForRoute(path string, op envelope) (CapabilityResourceAccess, error) {
	var access CapabilityResourceAccess
	switch path {
	case "/internal/agent/route", "/internal/agent/prepare", "/internal/agent/admit", "/internal/agent/child", "/internal/agent/cancel", "/internal/agent/gather", "/internal/agent/admission-state":
		access = CapabilityResourceAccess{"agent.delegate", "agent_installation", op.Context.InstallationID}
	case "/internal/model/generate", "/internal/model/receipt", "/internal/context/prepare", "/internal/runtime/harness-policy":
		access = CapabilityResourceAccess{"model.generate", "model", op.Context.ModelProfileID}
	case "/internal/model/embed", "/internal/model/embed/receipt":
		access = CapabilityResourceAccess{"model.embed", "model", op.Context.ModelProfileID}
	case "/internal/skill/load":
		var input struct {
			SkillID string `json:"skill_id"`
		}
		if json.Unmarshal(op.Input, &input) != nil {
			return access, errors.New("invalid skill input")
		}
		access = CapabilityResourceAccess{"skill.load", "skill", input.SkillID}
	case "/internal/knowledge/search", "/internal/knowledge/answer", "/internal/knowledge/answer/recovery":
		var input struct {
			Scope string `json:"knowledge_scope"`
		}
		if json.Unmarshal(op.Input, &input) != nil {
			return access, errors.New("invalid knowledge input")
		}
		access = CapabilityResourceAccess{"knowledge.search", "knowledge", input.Scope}
	case "/internal/knowledge/replay":
		access = CapabilityResourceAccess{"knowledge.search", "knowledge", op.Context.KnowledgeScope}
	case "/internal/tool/invoke", "/internal/tool/receipt", "/internal/permission/check":
		var input struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(op.Input, &input) != nil {
			return access, errors.New("invalid tool input")
		}
		access = CapabilityResourceAccess{"tool.invoke", "tool", input.Name}
	case "/internal/memory/access", "/internal/state/checkpoint":
		var input struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(op.Input, &input) != nil {
			return access, errors.New("invalid memory input")
		}
		switch strings.ToLower(strings.TrimSpace(input.Operation)) {
		case "load":
			access = CapabilityResourceAccess{"memory.read", "memory", op.Context.MemoryPolicyID}
		case "save":
			access = CapabilityResourceAccess{"memory.write", "memory", op.Context.MemoryPolicyID}
		default:
			return access, errors.New("invalid memory operation")
		}
	}
	if access.Action != "" && (access.ResourceID == "" || strings.TrimSpace(access.ResourceID) != access.ResourceID || strings.ContainsAny(access.ResourceID, "*\x00\r\n")) {
		return access, errors.New("invalid capability resource")
	}
	return access, nil
}
