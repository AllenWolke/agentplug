package permissionresources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (r PublishedResolver) ResolveAgentUsePackage(ctx context.Context, scope sharedkernel.Scope) (identity.AgentUsePackage, error) {
	if r.catalog == nil || r.policies == nil || scope.Validate() != nil || scope.InstallationID == "" || scope.AgentInstanceID != scope.InstallationID {
		return identity.AgentUsePackage{}, identity.ErrInvalidResource
	}
	installation, err := resolvePublishedInstallation(ctx, r.catalog, scope, scope.InstallationID)
	if err != nil {
		return identity.AgentUsePackage{}, err
	}
	scope.AgentID, scope.AgentVersionID = installation.AgentID, installation.AgentVersionID
	policy, err := r.policies.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil {
		return identity.AgentUsePackage{}, err
	}
	if policy.Validate() != nil || policy.ValidateDetails() != nil {
		return identity.AgentUsePackage{}, identity.ErrInvalidResource
	}
	resources := []identity.AgentUseResource{}
	for _, action := range []string{"discover", "run", "cancel", "history.read", "history.continue"} {
		resources = append(resources, identity.AgentUseResource{Type: "agent_installation", ID: scope.InstallationID, Action: action})
	}
	for _, action := range []string{"model.generate", "model.embed"} {
		resources = append(resources, identity.AgentUseResource{Type: "model", ID: policy.ModelProfileID, Action: action})
	}
	for _, id := range policy.Tool.AllowedTools {
		resources = append(resources, identity.AgentUseResource{Type: "tool", ID: id, Action: "tool.invoke"})
	}
	for _, id := range policy.Knowledge.AllowedScopes {
		resources = append(resources, identity.AgentUseResource{Type: "knowledge", ID: id, Action: "knowledge.search"})
	}
	for _, action := range []string{"memory.read", "memory.write"} {
		resources = append(resources, identity.AgentUseResource{Type: "memory", ID: policy.MemoryPolicyID, Action: action})
	}
	for _, id := range policy.Runtime.AllowedSkills {
		resources = append(resources, identity.AgentUseResource{Type: "skill", ID: id, Action: "skill.load"})
	}
	// Older approved snapshots have opaque content_hash values. Fingerprint the
	// complete resolved material instead of treating that label as a SHA-256.
	raw, err := json.Marshal(policy)
	if err != nil {
		return identity.AgentUsePackage{}, err
	}
	digest := sha256.Sum256(raw)
	return identity.NewAgentUsePackage(identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}, installation.AgentID, installation.AgentVersionID, hex.EncodeToString(digest[:]), resources, installation.DisplayName)
}
