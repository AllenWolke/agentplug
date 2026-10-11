package identity

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type MigrationMapping struct {
	ExpectedSourceDigest string             `json:"expected_source_digest"`
	Basis                string             `json:"basis"`
	Target               PermissionSnapshot `json:"target"`
}

type MigrationFactDifference struct {
	Kind   string          `json:"kind"`
	ID     string          `json:"id"`
	Change string          `json:"change"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

type MigrationMappingIssue struct {
	Code string `json:"code"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type MigrationShadowSample struct {
	Query            PermissionQuery     `json:"query"`
	Old              *PermissionDecision `json:"old,omitempty"`
	Target           PermissionDecision  `json:"target"`
	Classification   string              `json:"classification"`
	ScopeOnly        bool                `json:"scope_only"`
	UnverifiedReason string              `json:"unverified_reason,omitempty"`
}

type MigrationMappingPreview struct {
	PreviewOnly               bool                      `json:"preview_only"`
	ResourceOwnershipVerified bool                      `json:"resource_ownership_verified"`
	SourceDigest              string                    `json:"source_digest"`
	SourcePolicyMode          string                    `json:"source_policy_mode"`
	AuthenticationDigest      string                    `json:"authentication_digest"`
	Basis                     string                    `json:"basis"`
	EvaluatedAt               time.Time                 `json:"evaluated_at"`
	Target                    PermissionSnapshot        `json:"target"`
	Differences               []MigrationFactDifference `json:"differences"`
	Issues                    []MigrationMappingIssue   `json:"issues"`
	Samples                   []MigrationShadowSample   `json:"samples"`
	Digest                    string                    `json:"digest"`
}

// PreviewMigrationMapping compares explicit mappings. It supplies neither an
// appointment nor a commit authorization. Resource ownership must additionally
// be resolved by each owning module in the database-copy rehearsal.
func PreviewMigrationMapping(source MigrationSource, mapping MigrationMapping, queries []PermissionQuery, now time.Time) (MigrationMappingPreview, error) {
	result := MigrationMappingPreview{PreviewOnly: true, SourceDigest: source.SourceDigest, SourcePolicyMode: source.Snapshot.Mode, AuthenticationDigest: source.AuthenticationDigest, Basis: mapping.Basis, EvaluatedAt: now.UTC(), Differences: []MigrationFactDifference{}, Issues: []MigrationMappingIssue{}, Samples: []MigrationShadowSample{}}
	digest, err := migrationSourceDigest(source)
	if err != nil {
		return result, err
	}
	if source.SourceDigest == "" || digest != source.SourceDigest || mapping.ExpectedSourceDigest != source.SourceDigest {
		return result, ErrPermissionPlanStale
	}
	if now.IsZero() || strings.TrimSpace(mapping.Basis) == "" || len(mapping.Basis) > 1000 || len(queries) > 1000 {
		return result, ErrInvalidResource
	}
	// Own every slice and pointer: a caller cannot mutate a reviewed target via
	// the returned report, and preview must never normalize the original input.
	raw, err := json.Marshal(mapping.Target)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(raw, &result.Target); err != nil {
		return result, err
	}
	target := result.Target
	if target.Mode != "v2" || !migrationEqual(source.Snapshot.Principal, target.Principal) || !migrationEqual(source.Snapshot.Roles, target.Roles) || !migrationSliceEqual(source.Snapshot.Assignments, target.Assignments) || !migrationEqual(source.Snapshot.Delegations, target.Delegations) {
		return result, ErrInvalidResource
	}
	if source.Snapshot.Mode != "legacy" && source.Snapshot.Mode != "shadow" && source.Snapshot.Mode != "v2" {
		return result, ErrInvalidResource
	}
	issue := func(code, kind, id string) {
		result.Issues = append(result.Issues, MigrationMappingIssue{code, kind, id})
	}
	principal := target.Principal
	if !validPermissionResourceID(principal.ID) || !validPermissionResourceID(principal.TenantID) || (principal.Type != PrincipalUser && principal.Type != PrincipalServicePrincipal) {
		return result, ErrInvalidPrincipal
	}
	for _, m := range target.Memberships {
		if !validPermissionResourceID(m.ID) || m.SubjectID != principal.ID || m.Scope.Validate() != nil || m.Scope.TenantID != principal.TenantID || m.Validity.Validate() != nil || !migrationStatusValid(m.Status) || m.Revision == 0 || principal.Type != PrincipalUser {
			return result, ErrInvalidResource
		}
	}
	for _, b := range target.Bindings {
		if !validPermissionResourceID(b.ID) || b.SubjectID != principal.ID || b.Scope.Validate() != nil || (b.Scope.Type != "global" && b.Scope.TenantID != principal.TenantID) || b.Validity.Validate() != nil || !migrationStatusValid(b.Status) || b.Revision == 0 || principal.Type != PrincipalUser {
			return result, ErrInvalidResource
		}
		found := false
		for _, role := range target.Roles {
			if role.Code == b.RoleCode && role.Version == b.RoleVersion && slices.Contains(role.ScopeTypes, b.Scope.Type) {
				found = true
			}
		}
		if !found {
			return result, ErrInvalidResource
		}
		if b.Status == "active" && protectedAdministratorBinding(b) {
			unchanged := false
			for _, old := range source.Snapshot.Bindings {
				if old.ID == b.ID && migrationEqual(old, b) {
					unchanged = true
				}
			}
			if !unchanged || source.Snapshot.Mode != "v2" {
				issue("VERIFIED_ADMIN_APPOINTMENT_REQUIRED", "role_binding", b.ID)
			}
		}
	}
	for _, g := range target.Grants {
		if g.Validate() != nil || g.Validity.Validate() != nil || !validPermissionResourceID(g.ID) || g.SubjectType != principal.Type || g.SubjectID != principal.ID || g.TenantID != principal.TenantID {
			return result, ErrInvalidResource
		}
		if g.Status != "active" {
			continue
		}
		known := false
		for _, action := range BuiltinPermissionActions() {
			if action.Code == g.Action && !action.Management && action.ResourceType == g.ResourceType {
				known = true
			}
		}
		if !known || g.DataScope.Validate() != nil || !validPermissionResourceID(g.ResourceID) || !validPermissionResourceID(g.AgentInstanceID) || (g.ResourceType == "agent_installation" && g.ResourceID != g.AgentInstanceID) {
			issue("GRANT_TARGET_UNRESOLVED", "grant", g.ID)
		}
	}
	for _, old := range source.Snapshot.Grants {
		var next *Grant
		for i := range target.Grants {
			if target.Grants[i].ID == old.ID {
				next = &target.Grants[i]
				break
			}
		}
		if old.Status != "active" && (next == nil || !migrationEqual(old, *next)) {
			issue("REVOKED_GRANT_MUST_BE_PRESERVED", "grant", old.ID)
		}
		if old.Effect == "deny" && (next == nil || !migrationDenyPreserved(source.Snapshot.Mode, old, *next)) {
			issue("DENY_MUST_BE_PRESERVED", "grant", old.ID)
		}
		if source.Snapshot.Mode != "v2" && old.Effect == "deny" && old.Status == "active" && next != nil && (next.StartsAt != nil || next.ExpiresAt != nil) {
			issue("LEGACY_DENY_TIME_BOUNDARY_REQUIRES_REVIEW", "grant", old.ID)
		}
	}
	for _, old := range source.Snapshot.Bindings {
		if old.Status != "active" || !protectedAdministratorBinding(old) {
			continue
		}
		unchanged := false
		for _, next := range target.Bindings {
			if next.ID == old.ID && migrationEqual(old, next) {
				unchanged = true
			}
		}
		if !unchanged {
			issue("PROTECTED_ADMIN_CHANGE_REQUIRES_REVIEW", "role_binding", old.ID)
		}
	}
	for _, pair := range []struct {
		kind          string
		before, after any
	}{
		{"membership", source.Snapshot.Memberships, target.Memberships},
		{"role_binding", source.Snapshot.Bindings, target.Bindings},
		{"grant", source.Snapshot.Grants, target.Grants},
	} {
		diffs, err := migrationFactDiff(pair.kind, pair.before, pair.after)
		if err != nil {
			return result, err
		}
		result.Differences = append(result.Differences, diffs...)
	}
	queryBytes, err := json.Marshal(queries)
	if err != nil {
		return result, err
	}
	var ownedQueries []PermissionQuery
	if err := json.Unmarshal(queryBytes, &ownedQueries); err != nil {
		return result, err
	}
	for _, q := range ownedQueries {
		q.Now = now
		sample, err := migrationShadowSample(source.Snapshot, target, q)
		if err != nil {
			return result, err
		}
		result.Samples = append(result.Samples, sample)
		if sample.Classification == "permission_added" {
			issue("PERMISSION_ADDITION_REQUIRES_REVIEW", "sample", q.Action)
		}
	}
	raw, err = json.Marshal(result)
	if err != nil {
		return result, err
	}
	result.Digest = permissionHash(raw)
	return result, nil
}

func migrationStatusValid(status string) bool { return status == "active" || status == "revoked" }
func migrationSliceEqual[T any](a, b []T) bool {
	return len(a) == 0 && len(b) == 0 || migrationEqual(a, b)
}
func migrationEqual(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}

func migrationDenyPreserved(mode string, old, next Grant) bool {
	if mode == "v2" || old.Status != "active" {
		return migrationEqual(old, next)
	}
	// Predecessor denies had no typed resource or data scope, and denied every
	// object of that installation. Explicit metadata enrichment must retain
	// that breadth, action, status, time boundaries, provenance and revision.
	if next.ResourceType != "agent_installation" || next.ResourceID != old.AgentInstanceID || next.DataScope.Type != "approved_organization" || len(next.DataScope.IDs) != 0 {
		return false
	}
	if old.ResourceType != "" && old.ResourceType != next.ResourceType || old.ResourceID != "" && old.ResourceID != next.ResourceID {
		return false
	}
	next.ResourceType, next.ResourceID, next.DataScope = old.ResourceType, old.ResourceID, old.DataScope
	return migrationEqual(old, next)
}

func migrationFactDiff(kind string, before, after any) ([]MigrationFactDifference, error) {
	read := func(value any) (map[string]json.RawMessage, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		index := map[string]json.RawMessage{}
		for _, item := range items {
			var identity struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(item, &identity); err != nil {
				return nil, err
			}
			if identity.ID == "" || index[identity.ID] != nil {
				return nil, ErrInvalidResource
			}
			index[identity.ID] = item
		}
		return index, nil
	}
	old, err := read(before)
	if err != nil {
		return nil, err
	}
	next, err := read(after)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for id := range old {
		ids = append(ids, id)
	}
	for id := range next {
		if old[id] == nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	diffs := []MigrationFactDifference{}
	for _, id := range ids {
		change := "retained"
		if old[id] == nil {
			change = "added"
		} else if next[id] == nil {
			change = "removed"
		} else if string(old[id]) != string(next[id]) {
			change = "changed"
		}
		diffs = append(diffs, MigrationFactDifference{kind, id, change, old[id], next[id]})
	}
	return diffs, nil
}

func migrationShadowSample(old, target PermissionSnapshot, q PermissionQuery) (MigrationShadowSample, error) {
	sample := MigrationShadowSample{Query: q, Classification: "unverified", ScopeOnly: q.Object == nil}
	next, err := EvaluatePermission(target, q)
	if err != nil {
		return sample, err
	}
	sample.Target = next
	var previous PermissionDecision
	if old.Mode == "v2" {
		previous, err = EvaluatePermission(old, q)
	} else {
		for _, action := range BuiltinPermissionActions() {
			if action.Code == q.Action && action.Management {
				sample.UnverifiedReason = "LEGACY_MANAGEMENT_ROUTE_PROBE_REQUIRED"
				return sample, nil
			}
		}
		if q.Scope.Type != "agent_installation" || q.ResourceType != "agent_installation" || q.ResourceID != q.Scope.ResourceID {
			sample.UnverifiedReason = "LEGACY_RESOURCE_ROUTE_PROBE_REQUIRED"
			return sample, nil
		}
		if !old.Principal.IsActive {
			previous = PermissionDecision{Reason: "PRINCIPAL_DISABLED"}
		} else {
			// Match the storage-backed CheckPrincipalAccess/ListGrants projection
			// before invoking its evaluator; unrelated rows are not route inputs.
			rules := []Grant{}
			for _, grant := range old.Grants {
				if grant.TenantID == q.Scope.TenantID && grant.DepartmentID == q.Scope.DepartmentID && grant.ApplicationID == q.Scope.ApplicationID && grant.AgentInstanceID == q.Scope.ResourceID && grant.SubjectType == old.Principal.Type && grant.SubjectID == old.Principal.ID && grant.Action == q.Action {
					rules = append(rules, grant)
				}
			}
			decision, e := EvaluateAccess(AccessContext{Principal: old.Principal, Action: q.Action, Scope: sharedkernel.Scope{TenantID: q.Scope.TenantID, DepartmentID: q.Scope.DepartmentID, ApplicationID: q.Scope.ApplicationID, AgentInstanceID: q.Scope.ResourceID, PrincipalID: old.Principal.ID, PrincipalType: string(old.Principal.Type)}}, rules)
			err = e
			previous = PermissionDecision{Allowed: decision.Allowed, Reason: decision.Reason}
		}
	}
	if err != nil {
		return sample, err
	}
	sample.Old = &previous
	if previous.Allowed && !next.Allowed {
		sample.Classification = "permission_removed"
	} else if !previous.Allowed && next.Allowed {
		sample.Classification = "permission_added"
	} else if previous.Allowed {
		sample.Classification = "allowed_both_compare_ranges"
	} else {
		sample.Classification = "denied_both_compare_reasons"
	}
	return sample, nil
}
