package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// The policy is an upper bound, never a personal role or resource grant. A
// persisted head means this department has explicitly entered managed mode;
// a missing head is the pre-migration state, not an empty managed policy.
type DepartmentAgentPolicy struct {
	TenantID      string                       `json:"tenant_id"`
	DepartmentID  string                       `json:"department_id"`
	Revision      uint64                       `json:"revision"`
	EntriesDigest string                       `json:"entries_digest"`
	Entries       []DepartmentAgentPolicyEntry `json:"entries"`
}

type DepartmentAgentPolicyEntry struct {
	ApplicationID  string            `json:"application_id"`
	InstallationID string            `json:"installation_id"`
	Actions        []string          `json:"actions"`
	ActionVersions map[string]uint64 `json:"action_versions,omitempty"`
	Validity
}

func normalizedDepartmentAgentEntries(entries []DepartmentAgentPolicyEntry) []DepartmentAgentPolicyEntry {
	result := append([]DepartmentAgentPolicyEntry{}, entries...)
	for i := range result {
		result[i].Actions = append([]string{}, result[i].Actions...)
		result[i].ActionVersions = maps.Clone(result[i].ActionVersions)
		if result[i].StartsAt != nil {
			value := *result[i].StartsAt
			result[i].StartsAt = &value
		}
		if result[i].ExpiresAt != nil {
			value := *result[i].ExpiresAt
			result[i].ExpiresAt = &value
		}
		slices.Sort(result[i].Actions)
	}
	slices.SortFunc(result, func(a, b DepartmentAgentPolicyEntry) int {
		if a.ApplicationID != b.ApplicationID {
			return strings.Compare(a.ApplicationID, b.ApplicationID)
		}
		return strings.Compare(a.InstallationID, b.InstallationID)
	})
	return result
}

func departmentAgentEntriesDigest(entries []DepartmentAgentPolicyEntry) string {
	raw, _ := json.Marshal(normalizedDepartmentAgentEntries(entries))
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validateDepartmentAgentEntry(entry DepartmentAgentPolicyEntry) error {
	if !validPermissionResourceID(entry.ApplicationID) || !validPermissionResourceID(entry.InstallationID) || entry.Validity.Validate() != nil || len(entry.Actions) == 0 || len(entry.Actions) > len(BuiltinPermissionActions()) {
		return ErrInvalidResource
	}
	seen := map[string]bool{}
	for _, code := range entry.Actions {
		if seen[code] {
			return ErrInvalidResource
		}
		seen[code] = true
		found := false
		for _, action := range BuiltinPermissionActions() {
			if action.Code == code && !action.Management {
				found = true
			}
		}
		if !found {
			return ErrInvalidResource
		}
	}
	return nil
}

func validatePersistedDepartmentAgentEntry(entry DepartmentAgentPolicyEntry, revision uint64) error {
	if validateDepartmentAgentEntry(entry) != nil || len(entry.ActionVersions) != len(entry.Actions) {
		return ErrInvalidResource
	}
	for _, action := range entry.Actions {
		if version := entry.ActionVersions[action]; version == 0 || version > revision {
			return ErrInvalidResource
		}
	}
	return nil
}

func departmentAgentEntryFor(policy *DepartmentAgentPolicy, application, installation string) *DepartmentAgentPolicyEntry {
	if policy != nil {
		for i := range policy.Entries {
			entry := &policy.Entries[i]
			if entry.ApplicationID == application && entry.InstallationID == installation {
				return entry
			}
		}
	}
	return nil
}

func constrainGrantToDepartmentPolicy(grant *Grant, policy *DepartmentAgentPolicy, now time.Time) (*DepartmentAgentPolicyEntry, error) {
	// Denials only restrict access and must survive a ceiling withdrawal.
	grant.DepartmentAgentActionVersion = 0
	if policy == nil || grant.Effect == "deny" {
		return nil, nil
	}
	entry := departmentAgentEntryFor(policy, grant.ApplicationID, grant.AgentInstanceID)
	if entry == nil || !slices.Contains(entry.Actions, grant.Action) || entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
		return nil, ErrPermissionDenied
	}
	if entry.StartsAt != nil {
		if grant.StartsAt == nil {
			value := *entry.StartsAt
			grant.StartsAt = &value
		} else if grant.StartsAt.Before(*entry.StartsAt) {
			return nil, ErrPermissionDenied
		}
	}
	if entry.ExpiresAt != nil {
		if grant.ExpiresAt == nil {
			value := *entry.ExpiresAt
			grant.ExpiresAt = &value
		} else if grant.ExpiresAt.After(*entry.ExpiresAt) {
			return nil, ErrPermissionDenied
		}
	}
	if grant.Validity.Validate() != nil {
		return nil, ErrPermissionDenied
	}
	return entry, nil
}

// Source versions are derived from the current policy, never from submitted
// metadata. Removing and restoring an action must not revive old subordinate
// grants; changing an unrelated action preserves valid independent sources.
func departmentAgentGrantSourceEffective(snapshot PermissionSnapshot, grant Grant) bool {
	if grant.DepartmentAgentActionVersion == 0 || grant.Action == "cancel" {
		return true
	}
	policy := departmentAgentPolicyFor(snapshot, grantAuthorizationScope(grant))
	entry := departmentAgentEntryFor(policy, grant.ApplicationID, grant.AgentInstanceID)
	return entry != nil && entry.ActionVersions[grant.Action] == grant.DepartmentAgentActionVersion
}

func departmentAgentPolicyFor(snapshot PermissionSnapshot, scope ManagementScope) *DepartmentAgentPolicy {
	for i := range snapshot.DepartmentAgentPolicies {
		policy := &snapshot.DepartmentAgentPolicies[i]
		if policy.TenantID == scope.TenantID && policy.DepartmentID == scope.DepartmentID {
			return policy
		}
	}
	return nil
}

func departmentMembershipCovers(snapshot PermissionSnapshot, scope ManagementScope, now time.Time) bool {
	for _, member := range snapshot.Memberships {
		if member.SubjectID == snapshot.Principal.ID && member.Status == "active" && member.Effective(now) && member.Scope.Type != "tenant" && member.Scope.Type != "global" && member.Scope.Contains(scope) {
			return true
		}
	}
	return false
}

// A managed department permits legacy cancellation only as recovery under
// still-effective original grants. The legacy row-only reader omits validity
// metadata; use the complete snapshot instead, retaining deny precedence.
func evaluateManagedLegacyCancellation(snapshot PermissionSnapshot, scope sharedkernel.Scope, now time.Time) (AccessDecision, error) {
	management := ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID}
	if (snapshot.Mode != "legacy" && snapshot.Mode != "shadow") || departmentAgentPolicyFor(snapshot, management) == nil || now.IsZero() {
		return AccessDecision{}, ErrInvalidResource
	}
	grants := []Grant{}
	for _, grant := range snapshot.Grants {
		if grant.SubjectType != snapshot.Principal.Type || grant.SubjectID != snapshot.Principal.ID || grant.TenantID != scope.TenantID || grant.DepartmentID != scope.DepartmentID || grant.ApplicationID != scope.ApplicationID || grant.AgentInstanceID != scope.AgentInstanceID || grant.Action != "cancel" || grant.Status != GrantActive {
			continue
		}
		if grant.Validity.Validate() != nil || grant.ResourceType != "" && (grant.ResourceType != "agent_installation" || grant.ResourceID != scope.AgentInstanceID) {
			return AccessDecision{}, ErrInvalidResource
		}
		if grant.Effective(now) {
			grants = append(grants, grant)
		}
	}
	return EvaluateAccess(AccessContext{Scope: scope, Principal: snapshot.Principal, Action: "cancel"}, grants)
}

// Cancel remains subject to its existing role, grant and execution ownership
// checks. Removing an Agent ceiling must not strand an already running task.
func departmentAgentBlockReason(snapshot PermissionSnapshot, query PermissionQuery) string {
	policy := departmentAgentPolicyFor(snapshot, query.Scope)
	if policy == nil || query.Action == "cancel" {
		return ""
	}
	if snapshot.Mode != "v2" {
		return "DEPARTMENT_PERMISSION_MIGRATION_REQUIRED"
	}
	if snapshot.Principal.Type == PrincipalUser && !departmentMembershipCovers(snapshot, query.Scope, query.Now) {
		return "DEPARTMENT_MEMBERSHIP_REQUIRED"
	}
	installation := query.ResourceID
	if query.ResourceType != "agent_installation" {
		installation = query.Scope.ResourceID
	}
	for _, entry := range policy.Entries {
		if entry.ApplicationID != query.Scope.ApplicationID || entry.InstallationID != installation {
			continue
		}
		if !entry.Validity.Effective(query.Now) {
			return "DEPARTMENT_AGENT_INACTIVE"
		}
		if !slices.Contains(entry.Actions, query.Action) {
			return "DEPARTMENT_AGENT_ACTION_DENIED"
		}
		return ""
	}
	return "DEPARTMENT_AGENT_NOT_APPROVED"
}
