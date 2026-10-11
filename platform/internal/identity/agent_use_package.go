package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Only published resource identifiers and ordinary owner-scoped use actions
// cross this port. Prompts, credentials, policy contents and model settings do not.
type AgentUseResource struct {
	Type   string `json:"resource_type"`
	ID     string `json:"resource_id"`
	Action string `json:"action"`
}

type AgentUsePackage struct {
	DisplayName    string             `json:"display_name,omitempty"`
	Scope          ManagementScope    `json:"scope"`
	AgentID        string             `json:"agent_id"`
	AgentVersionID string             `json:"agent_version_id"`
	PolicyDigest   string             `json:"policy_digest"`
	Digest         string             `json:"package_digest"`
	Resources      []AgentUseResource `json:"resources"`
}

type AgentUseSelection struct {
	Scope          ManagementScope `json:"scope"`
	AgentVersionID string          `json:"agent_version_id"`
	PackageDigest  string          `json:"package_digest"`
	Validity
}

type AgentUsePackageResolver interface {
	ResolveAgentUsePackage(context.Context, sharedkernel.Scope) (AgentUsePackage, error)
}

func validAgentUseDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func agentUseResourceAllowed(resource AgentUseResource, installation string) bool {
	if !validPermissionResourceID(resource.ID) {
		return false
	}
	switch resource.Type {
	case "agent_installation":
		return resource.ID == installation && slices.Contains([]string{"discover", "run", "cancel", "history.read", "history.continue"}, resource.Action)
	case "model":
		return resource.Action == "model.generate" || resource.Action == "model.embed"
	case "tool":
		return resource.Action == "tool.invoke"
	case "knowledge":
		return resource.Action == "knowledge.search"
	case "memory":
		return resource.Action == "memory.read" || resource.Action == "memory.write"
	case "skill":
		return resource.Action == "skill.load"
	}
	return false
}

// Canonicalization keeps the same package stable when a catalog enumerates
// resources in a different order. Duplicate or unsupported entries fail closed.
func NewAgentUsePackage(scope ManagementScope, agent, version, policyDigest string, resources []AgentUseResource, names ...string) (AgentUsePackage, error) {
	if scope.Validate() != nil || scope.Type != "agent_installation" || !validPermissionResourceID(agent) || !validPermissionResourceID(version) || !validAgentUseDigest(policyDigest) || len(resources) < 5 || len(resources) > 126 {
		return AgentUsePackage{}, ErrInvalidResource
	}
	result := AgentUsePackage{Scope: scope, AgentID: agent, AgentVersionID: version, PolicyDigest: policyDigest, Resources: append([]AgentUseResource(nil), resources...)}
	if len(names) > 1 {
		return AgentUsePackage{}, ErrInvalidResource
	}
	if len(names) == 1 {
		result.DisplayName = names[0]
	}
	slices.SortFunc(result.Resources, func(a, b AgentUseResource) int {
		return strings.Compare(a.Type+"\x00"+a.ID+"\x00"+a.Action, b.Type+"\x00"+b.ID+"\x00"+b.Action)
	})
	seen := map[string]bool{}
	for _, resource := range result.Resources {
		key := resource.Type + "\x00" + resource.ID + "\x00" + resource.Action
		if !agentUseResourceAllowed(resource, scope.ResourceID) || seen[key] {
			return AgentUsePackage{}, ErrInvalidResource
		}
		seen[key] = true
	}
	for _, action := range []string{"discover", "run", "cancel", "history.read", "history.continue"} {
		if !seen["agent_installation\x00"+scope.ResourceID+"\x00"+action] {
			return AgentUsePackage{}, ErrInvalidResource
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return AgentUsePackage{}, err
	}
	result.Digest = permissionHash(raw)
	return result, nil
}

func (s *SQLStore) resolveAgentUsePackage(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope) (AgentUsePackage, error) {
	resolver, ok := s.capabilityResourceResolver.(AgentUsePackageResolver)
	if !ok {
		return AgentUsePackage{}, ErrPermissionResourceResolverUnavailable
	}
	resolved, err := resolver.ResolveAgentUsePackage(ctx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: scope.ResourceID, AgentInstanceID: scope.ResourceID, PrincipalID: actor.PrincipalID, PrincipalType: actor.PrincipalType})
	if err != nil {
		return AgentUsePackage{}, err
	}
	canonical, err := NewAgentUsePackage(resolved.Scope, resolved.AgentID, resolved.AgentVersionID, resolved.PolicyDigest, resolved.Resources, resolved.DisplayName)
	if err != nil || canonical.Scope != scope || canonical.Digest != resolved.Digest {
		return AgentUsePackage{}, ErrInvalidResource
	}
	return canonical, nil
}

func authorizeAgentUsePackage(ctx context.Context, reader permissionReader, actor sharedkernel.Scope, scope ManagementScope, now time.Time) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || scope.Validate() != nil || scope.Type != "agent_installation" || scope.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	owner, err := loadPermissionSnapshot(ctx, reader, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if owner.Mode != "v2" || owner.Principal.ID != actor.PrincipalID || owner.Principal.TenantID != actor.TenantID || !owner.Principal.IsActive {
		return ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, reader, scope); err != nil {
		return err
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.change", Scope: scope, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	return nil
}

// This read never grants authority. Every generated role and Grant still passes
// the existing target-membership, company ceiling and delegation checks.
func (s *SQLStore) AgentUsePackage(ctx context.Context, actor sharedkernel.Scope, scope ManagementScope) (AgentUsePackage, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AgentUsePackage{}, err
	}
	defer tx.Rollback()
	if err := authorizeAgentUsePackage(ctx, tx, actor, scope, s.clock().UTC()); err != nil {
		return AgentUsePackage{}, err
	}
	result, err := s.resolveAgentUsePackage(ctx, actor, scope)
	if err != nil {
		return AgentUsePackage{}, err
	}
	return result, tx.Commit()
}

func (s *SQLStore) expandAgentUseAuthorization(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command *AuthorizationChangeCommand, displayName *string) error {
	selection := command.AgentUse
	if selection == nil {
		return nil
	}
	if command.SubjectType != PrincipalUser || command.SubjectID == actor.PrincipalID || command.Preset != nil || len(command.Bindings) != 0 || len(command.Grants) != 0 || selection.Validity.Validate() != nil || !validAgentUseDigest(selection.PackageDigest) || !validPermissionResourceID(selection.AgentVersionID) {
		return ErrInvalidResource
	}
	if err := authorizeAgentUsePackage(ctx, tx, actor, selection.Scope, s.clock().UTC()); err != nil {
		return err
	}
	pack, err := s.resolveAgentUsePackage(ctx, actor, selection.Scope)
	if err != nil {
		return err
	}
	if pack.Digest != selection.PackageDigest || pack.AgentVersionID != selection.AgentVersionID {
		return ErrPermissionPlanStale
	}
	*displayName = pack.DisplayName
	source := "agent-use:" + command.IdempotencyKey
	key, err := json.Marshal([]any{command.SubjectID, source, selection})
	if err != nil {
		return err
	}
	id := permissionHash(key)
	command.Bindings = []RoleBinding{{ID: "binding-" + id, SubjectID: command.SubjectID, RoleCode: "operator", RoleVersion: 2, Scope: selection.Scope, Validity: selection.Validity, Status: "active", Revision: 1, SourceID: source}}
	needsSkillRole := false
	for _, resource := range pack.Resources {
		raw, err := json.Marshal([]any{id, resource})
		if err != nil {
			return err
		}
		command.Grants = append(command.Grants, Grant{ID: "grant-" + permissionHash(raw), SubjectType: PrincipalUser, SubjectID: command.SubjectID,
			TenantID: selection.Scope.TenantID, DepartmentID: selection.Scope.DepartmentID, ApplicationID: selection.Scope.ApplicationID, AgentInstanceID: selection.Scope.ResourceID,
			ResourceType: resource.Type, ResourceID: resource.ID, Action: resource.Action, DataScope: DataScope{Type: "owner"}, Validity: selection.Validity,
			Effect: "allow", Status: "active", Revision: 1, SourceID: source})
		needsSkillRole = needsSkillRole || resource.Type == "skill"
	}
	if needsSkillRole {
		command.Bindings = append(command.Bindings, RoleBinding{ID: "binding-skill-" + id, SubjectID: command.SubjectID, RoleCode: "skill_user", RoleVersion: 2, Scope: selection.Scope, Validity: selection.Validity, Status: "active", Revision: 1, SourceID: source})
	}
	return nil
}
