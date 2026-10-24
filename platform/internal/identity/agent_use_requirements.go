package identity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Requirements come from Catalog's immutable published snapshot, never from
// the department manager or model output. They contain no endpoints or secrets.
type AgentUseRequirement struct {
	ResourceType         string    `json:"resource_type"`
	ResourceID           string    `json:"resource_id"`
	Action               string    `json:"action"`
	DataScope            DataScope `json:"data_scope"`
	RequiresConfirmation bool      `json:"requires_confirmation,omitempty"`
}

type AgentUseRequirements struct {
	InstallationID string                `json:"installation_id"`
	AgentID        string                `json:"agent_id"`
	AgentVersionID string                `json:"agent_version_id"`
	DisplayName    string                `json:"display_name"`
	PolicyHash     string                `json:"policy_hash"`
	Requirements   []AgentUseRequirement `json:"requirements"`
	Digest         string                `json:"digest"`
}

type AgentUseRequirementsResolver interface {
	ResolveAgentUseRequirements(context.Context, sharedkernel.Scope) (AgentUseRequirements, error)
}

func (r *AgentUseRequirements) Seal() error {
	if !validPermissionResourceID(r.InstallationID) || !validPermissionResourceID(r.AgentID) || !validPermissionResourceID(r.AgentVersionID) || len(r.PolicyHash) != 64 || len(r.Requirements) > 64 {
		return ErrInvalidResource
	}
	if _, err := hex.DecodeString(r.PolicyHash); err != nil {
		return ErrInvalidResource
	}
	r.Requirements = append([]AgentUseRequirement(nil), r.Requirements...)
	slices.SortFunc(r.Requirements, func(a, b AgentUseRequirement) int { return compareRequirement(a, b) })
	seen := map[string]bool{}
	for _, item := range r.Requirements {
		key := item.ResourceType + "\x00" + item.ResourceID + "\x00" + item.Action
		if seen[key] || !validPermissionResourceID(item.ResourceID) || item.DataScope.Validate() != nil || len(item.DataScope.IDs) != 0 {
			return ErrInvalidResource
		}
		seen[key] = true
		valid := false
		for _, action := range BuiltinPermissionActions() {
			if !action.Management && !action.Sensitive && action.Code == item.Action && action.ResourceType == item.ResourceType {
				valid = true
			}
		}
		if !valid || !slices.Contains([]string{"model", "tool", "knowledge", "memory", "skill", "agent_installation"}, item.ResourceType) {
			return ErrInvalidResource
		}
		if item.ResourceType == "memory" {
			if item.DataScope.Type != "owner" {
				return ErrInvalidResource
			}
		} else if item.DataScope.Type != "approved_organization" {
			return ErrInvalidResource
		}
		if item.ResourceType == "agent_installation" && (item.ResourceID != r.InstallationID || item.Action != "agent.delegate") {
			return ErrInvalidResource
		}
	}
	copied := *r
	copied.Digest = ""
	copied.DisplayName = ""
	raw, err := json.Marshal(copied)
	if err != nil {
		return err
	}
	r.Digest = permissionHash(raw)
	return nil
}

func compareRequirement(a, b AgentUseRequirement) int {
	return slices.Compare([]string{a.ResourceType, a.ResourceID, a.Action}, []string{b.ResourceType, b.ResourceID, b.Action})
}
