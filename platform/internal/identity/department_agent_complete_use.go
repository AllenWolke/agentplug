package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const maximumDepartmentAgentFacts = 2048

func hasAgentPackageStamp(g Grant) bool {
	return g.AgentUsePackageID != "" || g.AgentUsePackageRevision != 0 || g.AgentUseRequirementsDigest != ""
}

func validAgentPackageStamp(g Grant) bool {
	scope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
	_, err := hex.DecodeString(g.AgentUseRequirementsDigest)
	return scope.Validate() == nil && validPermissionResourceID(g.AgentInstanceID) && g.AgentUsePackageID == departmentAgentPackageID(scope, g.AgentInstanceID) && g.AgentUsePackageRevision > 0 && len(g.AgentUseRequirementsDigest) == 64 && err == nil
}

// Only the dedicated, server-expanded workflow can create these stamps.
// Revoking a package dependency does not require that its old approval still
// exists or is active; expired and superseded rights must remain removable.
func validStampedAgentDependency(g Grant) bool {
	if !validAgentPackageStamp(g) || !validPermissionResourceID(g.ResourceID) || len(g.DataScope.IDs) != 0 {
		return false
	}
	if g.ResourceType == "memory" {
		return g.DataScope.Type == "owner" && slices.Contains([]string{"memory.read", "memory.write"}, g.Action)
	}
	if g.DataScope.Type != "approved_organization" {
		return false
	}
	switch g.ResourceType {
	case "model":
		return g.Action == "model.generate" || g.Action == "model.embed"
	case "tool":
		return g.Action == "tool.invoke"
	case "knowledge":
		return g.Action == "knowledge.search"
	case "skill":
		return g.Action == "skill.load"
	case "agent_installation":
		return g.ResourceID == g.AgentInstanceID && g.Action == "agent.delegate"
	}
	return false
}

func intersectAgentPackageValidity(request, approval Validity) (Validity, error) {
	value := request
	if approval.StartsAt != nil && (value.StartsAt == nil || approval.StartsAt.After(*value.StartsAt)) {
		start := *approval.StartsAt
		value.StartsAt = &start
	}
	if approval.ExpiresAt != nil && (value.ExpiresAt == nil || approval.ExpiresAt.Before(*value.ExpiresAt)) {
		end := *approval.ExpiresAt
		value.ExpiresAt = &end
	}
	return value, value.Validate()
}

// Called only after validating the original department purpose and the exact
// five basic-use grants. No client-supplied resource IDs or roles enter here.
func (s *SQLStore) expandApprovedDepartmentAgentUse(ctx context.Context, reader permissionReader, actor sharedkernel.Scope, original AuthorizationChangeCommand, expanded *AuthorizationChangeCommand, now time.Time) error {
	inspection, err := s.inspectDepartmentAgentPackages(ctx, reader, actor, *original.AgentSelection)
	if err != nil {
		return err
	}
	qualified := map[string]bool{}
	for _, entry := range inspection.Entries {
		if !entry.Approved {
			if entry.Approval != nil && entry.Approval.Status == "active" && entry.Approval.Effective(now) {
				return ErrAgentPackageStale
			}
			return ErrAgentPackageApprovalRequired
		}
		approval := entry.Approval
		validity, err := intersectAgentPackageValidity(original.AgentSelection.Validity, approval.Validity)
		if err != nil {
			return ErrAgentPackageApprovalRequired
		}
		stamp := func(g *Grant) {
			g.AgentUsePackageID, g.AgentUsePackageRevision, g.AgentUseRequirementsDigest = approval.ID, approval.Revision, approval.Requirements.Digest
			g.Validity = validity
		}
		for i := range expanded.Grants {
			g := &expanded.Grants[i]
			if g.ApplicationID == entry.ApplicationID && g.AgentInstanceID == entry.Requirements.InstallationID {
				stamp(g)
			}
		}
		sourceInput, _ := json.Marshal([]string{original.SubjectID, original.IdempotencyKey, entry.ApplicationID, entry.Requirements.InstallationID})
		source := "department-agent-package:" + permissionHash(sourceInput)
		for _, requirement := range entry.Requirements.Requirements {
			g := Grant{TenantID: approval.Scope.TenantID, DepartmentID: approval.Scope.DepartmentID, ApplicationID: entry.ApplicationID, AgentInstanceID: entry.Requirements.InstallationID,
				SubjectType: PrincipalUser, SubjectID: original.SubjectID, ResourceType: requirement.ResourceType, ResourceID: requirement.ResourceID, Action: requirement.Action, DataScope: requirement.DataScope,
				Effect: "allow", Status: "active", Revision: 1, SourceID: source}
			stamp(&g)
			raw, _ := json.Marshal([]any{source, approval.ID, approval.Revision, requirement})
			g.ID = "grant-" + permissionHash(raw)
			if !validStampedAgentDependency(g) {
				return ErrInvalidResource
			}
			expanded.Grants = append(expanded.Grants, g)
			role := ""
			if requirement.ResourceType == "skill" {
				role = "skill_user"
			} else if requirement.Action == "agent.delegate" {
				role = "agent_delegate"
			}
			key := entry.ApplicationID + "\x00" + role
			if role != "" && !qualified[key] {
				qualified[key] = true
				raw, _ := json.Marshal([]string{original.SubjectID, original.IdempotencyKey, entry.ApplicationID, role})
				expanded.Bindings = append(expanded.Bindings, RoleBinding{ID: "binding-" + permissionHash(raw), SubjectID: original.SubjectID, RoleCode: role, RoleVersion: 2, Scope: approval.Scope,
					SourceID: "department-agent-package:" + permissionHash(raw), Validity: original.AgentSelection.Validity, Status: "active", Revision: 1})
			}
		}
	}
	if len(expanded.Bindings)+len(expanded.Grants)+len(expanded.Memberships) > maximumDepartmentAgentFacts {
		return ErrInvalidResource
	}
	return nil
}

func loadReferencedAgentPackages(ctx context.Context, reader permissionReader, snapshot *PermissionSnapshot) error {
	seen := map[string]bool{}
	for _, g := range snapshot.Grants {
		if g.Status != "active" || !hasAgentPackageStamp(g) || seen[g.AgentUsePackageID] {
			continue
		}
		if !validAgentPackageStamp(g) {
			return ErrInvalidResource
		}
		seen[g.AgentUsePackageID] = true
		scope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
		approval, err := readDepartmentAgentPackage(ctx, reader, scope, g.AgentInstanceID)
		if err != nil {
			return err
		}
		if approval != nil {
			snapshot.AgentPackages = append(snapshot.AgentPackages, *approval)
		}
	}
	return nil
}

func agentPackageAllowsGrant(snapshot PermissionSnapshot, g Grant, now time.Time) bool {
	if !hasAgentPackageStamp(g) {
		return true
	}
	if !validAgentPackageStamp(g) {
		return false
	}
	for _, approval := range snapshot.AgentPackages {
		if approval.ID != g.AgentUsePackageID || approval.Revision != g.AgentUsePackageRevision || approval.Status != "active" || !approval.Effective(now) || approval.Requirements.Digest != g.AgentUseRequirementsDigest ||
			approval.Scope.TenantID != g.TenantID || approval.Scope.DepartmentID != g.DepartmentID || approval.Scope.ApplicationID != g.ApplicationID || approval.InstallationID != g.AgentInstanceID {
			continue
		}
		if g.ResourceType == "agent_installation" && g.ResourceID == g.AgentInstanceID && g.DataScope.Type == "owner" && len(g.DataScope.IDs) == 0 && slices.Contains(basicAgentUseActions, g.Action) {
			return true
		}
		return slices.ContainsFunc(approval.Requirements.Requirements, func(r AgentUseRequirement) bool {
			return r.ResourceType == g.ResourceType && r.ResourceID == g.ResourceID && r.Action == g.Action && r.DataScope.Type == g.DataScope.Type && len(g.DataScope.IDs) == 0
		})
	}
	return false
}

func agentPackageMatchesVersion(snapshot PermissionSnapshot, g Grant, version string) bool {
	return slices.ContainsFunc(snapshot.AgentPackages, func(p DepartmentAgentPackage) bool {
		return p.ID == g.AgentUsePackageID && p.Requirements.AgentVersionID == version
	})
}

func (s *SQLStore) bindAgentPackagePublishedVersion(ctx context.Context, snapshot PermissionSnapshot, query *PermissionQuery) error {
	for _, g := range snapshot.Grants {
		if !hasAgentPackageStamp(g) || g.Status != "active" || g.Effect != "allow" || g.Action != query.Action || g.ResourceType != query.ResourceType || g.ResourceID != query.ResourceID ||
			!(ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}).Contains(query.Scope) {
			continue
		}
		if query.Scope.Type == "agent_installation" && query.Scope.ResourceID != g.AgentInstanceID {
			continue
		}
		if s.capabilityResourceResolver == nil {
			return ErrPermissionResourceResolverUnavailable
		}
		scope := sharedkernel.Scope{TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID, PrincipalType: string(snapshot.Principal.Type), PrincipalID: snapshot.Principal.ID, InstallationID: g.AgentInstanceID, AgentInstanceID: g.AgentInstanceID}
		resource, err := s.capabilityResourceResolver.ResolvePermissionResource(ctx, scope, "agent_installation", g.AgentInstanceID)
		if err != nil {
			return err
		}
		if resource.Type != "agent_installation" || resource.ID != scope.InstallationID || resource.InstallationID != scope.InstallationID || resource.TenantID != scope.TenantID || resource.DepartmentID != scope.DepartmentID || resource.ApplicationID != scope.ApplicationID || resource.AgentVersionID == "" {
			return ErrInvalidResource
		}
		query.PublishedAgentVersionID, query.RequirePublishedVersion = resource.AgentVersionID, true
		return nil
	}
	return nil
}

// Admission holds the exact approval row alongside IAM source locks. A
// concurrent company suspension cannot slip between permission and Run commit.
func lockExecutionAgentPackages(ctx context.Context, tx *sql.Tx, snapshot PermissionSnapshot, scope sharedkernel.Scope) error {
	for _, p := range snapshot.AgentPackages {
		if p.Scope.TenantID != scope.TenantID || p.Scope.DepartmentID != scope.DepartmentID || p.Scope.ApplicationID != scope.ApplicationID || p.InstallationID != scope.AgentInstanceID {
			continue
		}
		var revision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_department_agent_package WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND installation_id=? FOR SHARE`), p.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, p.InstallationID).Scan(&revision); err != nil {
			return err
		}
		if revision != p.Revision {
			return ErrPermissionExplanationStale
		}
	}
	return nil
}
