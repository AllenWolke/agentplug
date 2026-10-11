package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrPermissionDenied              = errors.New("permission denied")
	ErrPermissionPlanStale           = errors.New("authorization plan is stale")
	ErrPermissionRecorderUnavailable = errors.New("authorization change recorder is required")
)

func permissionHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type permissionReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type AuthorizationChangeCommand struct {
	Preset              *PresetSelection     `json:"preset,omitempty"`
	AgentUse            *AgentUseSelection   `json:"agent_use,omitempty"`
	SubjectType         PrincipalType        `json:"subject_type"`
	SubjectID           string               `json:"subject_id"`
	ExpectedRevision    uint64               `json:"expected_revision"`
	IdempotencyKey      string               `json:"idempotency_key"`
	Reason              string               `json:"reason"`
	Bindings            []RoleBinding        `json:"role_bindings,omitempty"`
	Grants              []Grant              `json:"resource_grants,omitempty"`
	Memberships         []MembershipMutation `json:"memberships,omitempty"`
	Assignments         []TaskAssignment     `json:"task_assignments,omitempty"`
	RevokeAssignmentIDs []string             `json:"revoke_assignment_ids,omitempty"`
	RevokeBindingIDs    []string             `json:"revoke_binding_ids,omitempty"`
	RevokeGrantIDs      []string             `json:"revoke_grant_ids,omitempty"`
	PlanDigest          string               `json:"plan_digest,omitempty"`
	PlanExpiresAt       time.Time            `json:"plan_expires_at,omitempty"`
}

type AuthorizationChangePlan struct {
	AgentUseDisplayName          string                     `json:"agent_use_display_name,omitempty"`
	Digest                       string                     `json:"plan_digest"`
	ExpiresAt                    time.Time                  `json:"plan_expires_at"`
	ActorID                      string                     `json:"actor_id"`
	SubjectID                    string                     `json:"subject_id"`
	BaselineRevision             uint64                     `json:"baseline_revision"`
	Command                      AuthorizationChangeCommand `json:"change"`
	ExpandedBindings             []RoleBinding              `json:"expanded_role_bindings"`
	ExpandedGrants               []Grant                    `json:"expanded_resource_grants"`
	ExpandedAssignments          []TaskAssignment           `json:"expanded_task_assignments"`
	AutomaticRevokeAssignmentIDs []string                   `json:"automatic_revoke_assignment_ids"`
	ExpandedMemberships          []Membership               `json:"expanded_memberships"`
	AutomaticRevokeBindingIDs    []string                   `json:"automatic_revoke_binding_ids"`
	AutomaticRevokeGrantIDs      []string                   `json:"automatic_revoke_grant_ids"`
}

type AuthorizationChangeReceipt struct {
	ID          string                     `json:"change_id"`
	ActorID     string                     `json:"actor_id"`
	SubjectID   string                     `json:"subject_id"`
	Revision    uint64                     `json:"revision"`
	PlanDigest  string                     `json:"plan_digest"`
	Reason      string                     `json:"reason"`
	OccurredAt  time.Time                  `json:"occurred_at"`
	Change      AuthorizationChangeCommand `json:"change"`
	Memberships []Membership               `json:"memberships,omitempty"`
}

type AuthorizationChangeRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error

func (s *SQLStore) SetAuthorizationChangeRecorder(recorder AuthorizationChangeRecorder) {
	s.authorizationChangeRecorder = recorder
}

// PermissionSnapshot uses a repeatable-read transaction so decisions never
// combine a new mode with old role/grant facts from another transaction.
func (s *SQLStore) PermissionSnapshot(ctx context.Context, kind PrincipalType, id string) (PermissionSnapshot, error) {
	if s == nil || s.db == nil {
		return PermissionSnapshot{}, errors.New("identity database is required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionSnapshot{}, err
	}
	defer tx.Rollback()
	result, err := loadPermissionSnapshot(ctx, tx, kind, id)
	if err != nil {
		return PermissionSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return PermissionSnapshot{}, err
	}
	return result, nil
}

func loadPermissionSnapshot(ctx context.Context, reader permissionReader, kind PrincipalType, id string) (PermissionSnapshot, error) {
	s := PermissionSnapshot{Mode: "legacy", Memberships: []Membership{}, Bindings: []RoleBinding{}, Roles: []RoleDefinition{}, Grants: []Grant{}, Delegations: []Delegation{}}
	var roles, groups string
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,principal_type,tenant_id,roles_json,groups_json,active,revision FROM platform_identity_principal WHERE principal_type=? AND id=?`), kind, id).Scan(&s.Principal.ID, &s.Principal.Type, &s.Principal.TenantID, &roles, &groups, &s.Principal.IsActive, &s.Principal.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrPrincipalNotFound
	}
	if err != nil {
		return s, err
	}
	if json.Unmarshal([]byte(roles), &s.Principal.Roles) != nil || json.Unmarshal([]byte(groups), &s.Principal.Groups) != nil {
		return s, ErrInvalidResource
	}
	err = reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type=? AND subject_id=?`), kind, id).Scan(&s.Mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return s, err
	}
	if s.Mode != "legacy" && s.Mode != "shadow" && s.Mode != "v2" {
		return s, ErrInvalidResource
	}
	for _, load := range []struct {
		query  string
		args   []any
		decode func([]byte) error
	}{
		{`SELECT payload FROM platform_identity_role_definition ORDER BY role_code,role_version`, nil, func(raw []byte) error {
			var v RoleDefinition
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			s.Roles = append(s.Roles, v)
			return nil
		}},
		{`SELECT payload FROM platform_identity_membership WHERE subject_id=? ORDER BY id`, []any{id}, func(raw []byte) error {
			var v Membership
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			s.Memberships = append(s.Memberships, v)
			return nil
		}},
		{`SELECT payload FROM platform_identity_role_binding WHERE subject_id=? ORDER BY id`, []any{id}, func(raw []byte) error {
			var v RoleBinding
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			s.Bindings = append(s.Bindings, v)
			return nil
		}},
		{`SELECT payload FROM platform_identity_delegation WHERE subject_id=? ORDER BY id`, []any{id}, func(raw []byte) error {
			var v Delegation
			if err := json.Unmarshal(raw, &v); err != nil {
				return err
			}
			s.Delegations = append(s.Delegations, v)
			return nil
		}},
	} {
		rows, err := reader.QueryContext(ctx, sqlutil.Bind(load.query), load.args...)
		if err != nil {
			return s, err
		}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return s, err
			}
			if err := load.decode(raw); err != nil {
				rows.Close()
				return s, err
			}
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return s, err
		}
		if closeErr != nil {
			return s, closeErr
		}
	}
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,permission_json FROM platform_identity_grant WHERE subject_type=? AND subject_id=? ORDER BY id`), kind, id)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var g Grant
		var raw []byte
		if err := rows.Scan(&g.ID, &g.TenantID, &g.DepartmentID, &g.ApplicationID, &g.AgentInstanceID, &g.SubjectType, &g.SubjectID, &g.Action, &g.Effect, &g.Status, &g.Revision, &raw); err != nil {
			return s, err
		}
		if raw != nil {
			var metadata Grant
			if err := json.Unmarshal(raw, &metadata); err != nil {
				return s, err
			}
			g.Validity, g.ResourceType, g.ResourceID, g.DataScope, g.SourceID, g.PresetCode, g.PresetVersion, g.DelegationID = metadata.Validity, metadata.ResourceType, metadata.ResourceID, metadata.DataScope, metadata.SourceID, metadata.PresetCode, metadata.PresetVersion, metadata.DelegationID
			g.DepartmentAgentActionVersion = metadata.DepartmentAgentActionVersion
		}
		s.Grants = append(s.Grants, g)
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	if err := rows.Close(); err != nil {
		return s, err
	}
	if kind == PrincipalUser {
		s.Assignments, err = loadTaskAssignments(ctx, reader, id)
	}
	if err == nil {
		s.DepartmentAgentPolicies, err = loadDepartmentAgentPolicies(ctx, reader, s)
	}
	return s, err
}

func (s *SQLStore) PreviewAuthorizationChange(ctx context.Context, actor sharedkernel.Scope, command AuthorizationChangeCommand) (AuthorizationChangePlan, error) {
	if s == nil || s.db == nil {
		return AuthorizationChangePlan{}, errors.New("identity database is required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	defer tx.Rollback()
	plan, err := s.planAuthorizationChange(ctx, tx, actor, command, s.clock().UTC().Add(5*time.Minute))
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit()
}

func (s *SQLStore) planAuthorizationChange(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command AuthorizationChangeCommand, deadline time.Time) (AuthorizationChangePlan, error) {
	return s.planAuthorizationChangeTarget(ctx, tx, actor, command, deadline, nil)
}

func (s *SQLStore) planAuthorizationChangeTarget(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command AuthorizationChangeCommand, deadline time.Time, newTarget *PermissionSnapshot) (AuthorizationChangePlan, error) {
	// Own the command's slices and time pointers. Preview/commit normalization
	// must not mutate a caller's request shared by concurrent retries.
	copyBytes, err := json.Marshal(command)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	var copied AuthorizationChangeCommand
	if err := json.Unmarshal(copyBytes, &copied); err != nil {
		return AuthorizationChangePlan{}, err
	}
	command = copied
	originalCommand := command
	command.Assignments = append([]TaskAssignment(nil), command.Assignments...)
	if command.Preset != nil {
		if len(command.Bindings) != 0 || len(command.Grants) != 0 {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_preset_definition WHERE preset_code=? AND preset_version=?`), command.Preset.Code, command.Preset.Version).Scan(&raw); err != nil {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		var preset IdentityPreset
		if err := json.Unmarshal(raw, &preset); err != nil {
			return AuthorizationChangePlan{}, err
		}
		bindings, grants, err := ExpandIdentityPreset(preset, command.SubjectType, command.SubjectID, "preset:"+command.IdempotencyKey, *command.Preset)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
		command.Bindings, command.Grants = bindings, grants
	}
	agentUseDisplayName := ""
	if err := s.expandAgentUseAuthorization(ctx, tx, actor, &command, &agentUseDisplayName); err != nil {
		return AuthorizationChangePlan{}, err
	}
	// No administrator, including a global platform administrator, may use
	// direct grants or a preset to add their own business authority. Self-revoke
	// remains available and administrator continuity is checked separately.
	if command.SubjectType == PrincipalUser && strings.EqualFold(command.SubjectID, actor.PrincipalID) && (len(command.Bindings) > 0 || len(command.Grants) > 0 || len(command.Assignments) > 0) {
		return AuthorizationChangePlan{}, ErrPermissionDenied
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || command.SubjectID == "" || (command.SubjectType != PrincipalUser && command.SubjectType != PrincipalServicePrincipal) || command.ExpectedRevision == 0 || strings.TrimSpace(command.Reason) == "" || len(command.Reason) > 1000 || command.IdempotencyKey == "" || len(command.IdempotencyKey) > 128 {
		return AuthorizationChangePlan{}, ErrInvalidResource
	}
	count := len(command.Bindings) + len(command.Grants) + len(command.RevokeBindingIDs) + len(command.RevokeGrantIDs) + len(command.Memberships) + len(command.Assignments) + len(command.RevokeAssignmentIDs)
	if count == 0 || count > 128 {
		return AuthorizationChangePlan{}, ErrInvalidResource
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	if owner.Mode != "v2" || owner.Principal.TenantID != actor.TenantID {
		return AuthorizationChangePlan{}, ErrPermissionDenied
	}
	var target PermissionSnapshot
	if newTarget != nil {
		target = *newTarget
		target.Roles = owner.Roles
	} else {
		target, err = loadPermissionSnapshot(ctx, tx, command.SubjectType, command.SubjectID)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
	}
	if target.Mode != "v2" || !target.Principal.IsActive || target.Principal.Revision != command.ExpectedRevision {
		return AuthorizationChangePlan{}, ErrIdentityConflict
	}
	now := s.clock().UTC()
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return AuthorizationChangePlan{}, ErrPermissionPlanStale
	}
	baselineTargetDigest, err := PermissionSnapshotDigest(target)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	projectedMembers, expandedMembers, automaticBindings, automaticGrants, err := planMembershipMutations(ctx, tx, actor, owner, target, command, now)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	automaticAssignments := automaticAssignmentRevocations(target, command, projectedMembers, now)
	command.RevokeAssignmentIDs = mergePermissionRevocations(command.RevokeAssignmentIDs, automaticAssignments)
	target.Memberships = projectedMembers
	for _, id := range automaticBindings {
		if !slices.Contains(command.RevokeBindingIDs, id) {
			command.RevokeBindingIDs = append(command.RevokeBindingIDs, id)
		}
	}
	for _, id := range automaticGrants {
		if !slices.Contains(command.RevokeGrantIDs, id) {
			command.RevokeGrantIDs = append(command.RevokeGrantIDs, id)
		}
	}
	seen := map[string]bool{}
	planPolicies := []DepartmentAgentPolicy{}
	policyCache := map[string]*DepartmentAgentPolicy{}
	policyForScope := func(scope ManagementScope) (*DepartmentAgentPolicy, error) {
		if scope.DepartmentID == "" {
			return nil, nil
		}
		key := scope.TenantID + "\x00" + scope.DepartmentID
		if policy, ok := policyCache[key]; ok {
			return policy, nil
		}
		policy, managed, err := readDepartmentAgentPolicy(ctx, tx, scope.TenantID, scope.DepartmentID)
		if err != nil {
			return nil, err
		}
		if !managed {
			policyCache[key] = nil
			return nil, nil
		}
		policyCache[key] = &policy
		planPolicies = append(planPolicies, policy)
		return &policy, nil
	}
	checkScope := func(scope ManagementScope) error {
		if scope.Validate() != nil || scope.Type == "global" || scope.TenantID != target.Principal.TenantID {
			return ErrInvalidResource
		}
		if err := validatePermissionScope(ctx, tx, scope); err != nil {
			return err
		}
		if scope.Type == "agent_installation" {
			if s.permissionResourceResolver == nil {
				return ErrInvalidResource
			}
			if _, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}, scope.ResourceID); err != nil {
				return err
			}
		}
		member := command.SubjectType == PrincipalServicePrincipal
		for _, m := range target.Memberships {
			if m.SubjectID == target.Principal.ID && m.Status == "active" && m.Effective(now) && m.Scope.Contains(scope) {
				member = true
			}
		}
		if !member {
			return ErrPermissionDenied
		}
		policy, err := policyForScope(scope)
		if err != nil {
			return err
		}
		if policy != nil && command.SubjectType == PrincipalUser && !departmentMembershipCovers(target, scope, now) {
			return ErrPermissionDenied
		}
		return nil
	}
	authorize := func(scope ManagementScope, role, action, resource string, data DataScope, validity Validity) (string, error) {
		decision, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.change", Scope: scope, Now: now})
		if err != nil {
			return "", err
		}
		if !decision.Allowed {
			return "", ErrPermissionDenied
		}
		super := false
		for _, b := range owner.Bindings {
			if slices.Contains(decision.BindingIDs, b.ID) && b.RoleCode == "super_admin" {
				super = true
			}
		}
		if super {
			return "", nil
		}
		if command.SubjectID == actor.PrincipalID {
			return "", ErrPermissionDenied
		}
		for _, b := range target.Bindings {
			if b.Status == "active" && b.Effective(now) && protectedAdministratorBinding(b) {
				return "", ErrPermissionDenied
			}
		}
		if companyAdministrationAllows(owner, scope, "authorization.change", now) {
			return "", nil
		}
		if administrationKind(owner, now) == "department" {
			if command.SubjectType != PrincipalUser {
				return "", ErrPermissionDenied
			}
			if !departmentAdministrationAllows(owner, scope, "authorization.change", role, action, data, validity, now) {
				return "", ErrPermissionDenied
			}
			policy, err := policyForScope(scope)
			if err != nil {
				return "", err
			}
			// A managed company's ceiling replaces per-Agent delegation lists.
			// Grant creation is checked against its precise installation below;
			// old grants remain revocable after a ceiling entry is removed.
			if policy != nil && (role != "" || action != "") {
				return "", nil
			}
		}
		for _, d := range owner.Delegations {
			if d.Covers(actor.PrincipalID, "authorization.change", role, action, resource, scope, data, validity, now) {
				return d.ID, nil
			}
		}
		return "", ErrPermissionDenied
	}
	for i := range command.Bindings {
		b := &command.Bindings[i]
		if command.Preset == nil && (b.PresetCode != "" || b.PresetVersion != 0) {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		if b.ID == "" || seen[b.ID] || b.SubjectID != command.SubjectID || command.SubjectType != PrincipalUser || b.RoleVersion == 0 || b.SourceID == "" || protectedAdministratorBinding(*b) || b.Status != "active" || b.Revision != 1 || b.Validity.Validate() != nil {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		seen[b.ID] = true
		if err := checkScope(b.Scope); err != nil {
			return AuthorizationChangePlan{}, err
		}
		roleFound := false
		for _, role := range target.Roles {
			if role.Code == b.RoleCode && role.Version == b.RoleVersion && role.Assignable && slices.Contains(role.ScopeTypes, b.Scope.Type) {
				roleFound = true
			}
		}
		if !roleFound {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		// Old delegations enumerate role codes, not versions. They must not
		// silently acquire the new department administration capability.
		if b.RoleCode == "department_admin" && b.RoleVersion == 2 {
			appointment, err := EvaluatePermission(owner, PermissionQuery{Action: "administrator.appoint", Scope: ManagementScope{Type: "global"}, Now: now})
			if err != nil {
				return AuthorizationChangePlan{}, err
			}
			if !appointment.Allowed && !companyAdministrationAllows(owner, b.Scope, "authorization.change", now) {
				return AuthorizationChangePlan{}, ErrPermissionDenied
			}
		}
		delegation, err := authorize(b.Scope, b.RoleCode, "", "", DataScope{}, b.Validity)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
		b.DelegationID = delegation
	}
	for i := range command.Grants {
		g := &command.Grants[i]
		if command.Preset == nil && (g.PresetCode != "" || g.PresetVersion != 0) {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		if g.ID == "" || seen[g.ID] || g.SubjectID != command.SubjectID || g.SubjectType != command.SubjectType || g.SourceID == "" || g.DataScope.Validate() != nil || g.Validity.Validate() != nil || g.Revision != 1 || g.Status != "active" || g.Effect != "allow" && g.Effect != "deny" {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		seen[g.ID] = true
		scope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
		if err := checkScope(scope); err != nil {
			return AuthorizationChangePlan{}, err
		}
		known := false
		for _, a := range BuiltinPermissionActions() {
			if !a.Management && a.Code == g.Action && a.ResourceType == g.ResourceType {
				known = true
			}
		}
		if !known {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		if err := s.validateGrantResource(ctx, *g); err != nil {
			return AuthorizationChangePlan{}, err
		}
		policy, err := policyForScope(scope)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
		entry, err := constrainGrantToDepartmentPolicy(g, policy, now)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
		delegation, err := authorize(grantAuthorizationScope(*g), "", g.Action, g.ResourceID, g.DataScope, g.Validity)
		if err != nil {
			return AuthorizationChangePlan{}, err
		}
		g.DelegationID = delegation
		if entry != nil && administrationKind(owner, now) == "department" {
			g.DepartmentAgentActionVersion = entry.ActionVersions[g.Action]
		}
	}
	for _, id := range command.RevokeBindingIDs {
		if id == "" || seen[id] {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		seen[id] = true
		found := false
		for _, b := range target.Bindings {
			if b.ID == id && b.Status == "active" {
				found = true
				if protectedAdministratorBinding(b) {
					return AuthorizationChangePlan{}, ErrPermissionDenied
				}
				if _, err := authorize(b.Scope, b.RoleCode, "", "", DataScope{}, b.Validity); err != nil && !slices.Contains(automaticBindings, id) {
					return AuthorizationChangePlan{}, err
				}
			}
		}
		if !found {
			return AuthorizationChangePlan{}, ErrIdentityConflict
		}
	}
	for _, id := range command.RevokeGrantIDs {
		if id == "" || seen[id] {
			return AuthorizationChangePlan{}, ErrInvalidResource
		}
		seen[id] = true
		found := false
		for _, g := range target.Grants {
			if g.ID == id && g.Status == "active" {
				found = true
				scope := grantAuthorizationScope(g)
				if _, err := authorize(scope, "", g.Action, g.ResourceID, g.DataScope, g.Validity); err != nil && !slices.Contains(automaticGrants, id) {
					return AuthorizationChangePlan{}, err
				}
			}
		}
		if !found {
			return AuthorizationChangePlan{}, ErrIdentityConflict
		}
	}
	if err := s.planTaskAssignmentChanges(ctx, actor, target, &command, automaticAssignments, seen, checkScope, authorize); err != nil {
		return AuthorizationChangePlan{}, err
	}
	command.PlanDigest = ""
	command.PlanExpiresAt = time.Time{}
	actorDigest, err := PermissionSnapshotDigest(owner)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	slices.SortFunc(planPolicies, func(a, b DepartmentAgentPolicy) int {
		if a.TenantID != b.TenantID {
			return strings.Compare(a.TenantID, b.TenantID)
		}
		return strings.Compare(a.DepartmentID, b.DepartmentID)
	})
	raw, err := json.Marshal(struct {
		Actor              string
		Target             string
		Deadline           time.Time
		Command            AuthorizationChangeCommand
		Members            []Membership
		DepartmentPolicies []DepartmentAgentPolicy
	}{actorDigest, baselineTargetDigest, deadline, command, expandedMembers, planPolicies})
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	originalCommand.PlanDigest = ""
	originalCommand.PlanExpiresAt = time.Time{}
	return AuthorizationChangePlan{AgentUseDisplayName: agentUseDisplayName, Digest: permissionHash(raw), ExpiresAt: deadline, ActorID: actor.PrincipalID, SubjectID: command.SubjectID, BaselineRevision: target.Principal.Revision, Command: originalCommand, ExpandedBindings: command.Bindings, ExpandedGrants: command.Grants, ExpandedAssignments: command.Assignments, ExpandedMemberships: expandedMembers, AutomaticRevokeBindingIDs: automaticBindings, AutomaticRevokeGrantIDs: automaticGrants, AutomaticRevokeAssignmentIDs: automaticAssignments}, nil
}

func validatePermissionScope(ctx context.Context, reader permissionReader, scope ManagementScope) error {
	if scope.Validate() != nil {
		return ErrInvalidResource
	}
	if scope.Type == "global" {
		return nil
	}
	var count int
	query := `SELECT COUNT(*) FROM platform_identity_tenant WHERE id=? AND status='active'`
	args := []any{scope.TenantID}
	if scope.DepartmentID != "" {
		query = `SELECT COUNT(*) FROM platform_identity_department d JOIN platform_identity_tenant t ON t.id=d.tenant_id WHERE d.id=? AND d.tenant_id=? AND d.status='active' AND t.status='active'`
		args = []any{scope.DepartmentID, scope.TenantID}
	}
	if scope.ApplicationID != "" {
		query = `SELECT COUNT(*) FROM platform_identity_application a JOIN platform_identity_department d ON d.id=a.department_id AND d.tenant_id=a.tenant_id JOIN platform_identity_tenant t ON t.id=a.tenant_id WHERE a.id=? AND a.department_id=? AND a.tenant_id=? AND a.status='active' AND d.status='active' AND t.status='active'`
		args = []any{scope.ApplicationID, scope.DepartmentID, scope.TenantID}
	}
	if err := reader.QueryRowContext(ctx, sqlutil.Bind(query), args...).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrScopeMismatch
	}
	return nil
}

func (s *SQLStore) CommitAuthorizationChange(ctx context.Context, actor sharedkernel.Scope, command AuthorizationChangeCommand) (AuthorizationChangeReceipt, error) {
	if s == nil || s.db == nil || s.authorizationChangeRecorder == nil {
		return AuthorizationChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || command.IdempotencyKey == "" || len(command.IdempotencyKey) > 128 {
		return AuthorizationChangeReceipt{}, ErrInvalidResource
	}
	requestCopy := command
	requestCopy.PlanDigest = ""
	requestCopy.PlanExpiresAt = time.Time{}
	raw, err := json.Marshal(requestCopy)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	requestDigest := permissionHash(raw)
	key := permissionHash([]byte(actor.PrincipalID + "\x00" + command.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	defer tx.Rollback()
	// All IAM writes and administrator lifecycle operations share this guard.
	// Serialize first, then take principal locks in deterministic order.
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	var digest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&digest, &saved)
	if err == nil {
		if digest != requestDigest {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
		}
		var receipt AuthorizationChangeReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return receipt, err
		}
		owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	ids := []string{actor.PrincipalID, command.SubjectID}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		kind := command.SubjectType
		if id == actor.PrincipalID {
			kind = PrincipalUser
		}
		var revision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type=? AND id=? FOR UPDATE`), kind, id).Scan(&revision); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	receipt, err := s.commitAuthorizationChangeTx(ctx, tx, actor, command, key, requestDigest)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

// The same transaction service is used by direct authorization, versioned
// user creation and approval; callers retain ownership of Commit/Rollback.
func (s *SQLStore) commitAuthorizationChangeTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command AuthorizationChangeCommand, key, requestDigest string) (AuthorizationChangeReceipt, error) {
	plan, err := s.planAuthorizationChange(ctx, tx, actor, command, command.PlanExpiresAt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if command.PlanDigest == "" || plan.Digest != command.PlanDigest {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	for i, member := range plan.ExpandedMemberships {
		if err := persistMembershipMutation(ctx, tx, member, plan.Command.Memberships[i].ExpectedRevision); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, b := range plan.ExpandedBindings {
		if err := insertRoleBinding(ctx, tx, b); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, g := range plan.ExpandedGrants {
		if err := insertPermissionGrant(ctx, tx, g, s.clock().UTC()); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, assignment := range plan.ExpandedAssignments {
		if err := insertTaskAssignment(ctx, tx, assignment); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, id := range mergePermissionRevocations(plan.Command.RevokeAssignmentIDs, plan.AutomaticRevokeAssignmentIDs) {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_task_assignment SET status='revoked',revision=revision+1 WHERE id=? AND subject_id=? AND status='active'`), id, command.SubjectID); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, id := range mergePermissionRevocations(plan.Command.RevokeBindingIDs, plan.AutomaticRevokeBindingIDs) {
		var payload []byte
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_role_binding WHERE id=? AND subject_id=? AND status='active' FOR UPDATE`), id, command.SubjectID).Scan(&payload); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		var b RoleBinding
		if err := json.Unmarshal(payload, &b); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		b.Status = "revoked"
		b.Revision++
		payload, err = json.Marshal(b)
		if err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=revision+1,payload=? WHERE id=? AND subject_id=?`), string(payload), id, command.SubjectID); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	for _, id := range mergePermissionRevocations(plan.Command.RevokeGrantIDs, plan.AutomaticRevokeGrantIDs) {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=? AND subject_type=? AND subject_id=? AND status='active'`), id, command.SubjectType, command.SubjectID); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type=? AND id=? AND revision=?`), command.SubjectType, command.SubjectID, command.ExpectedRevision)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if count != 1 {
		return AuthorizationChangeReceipt{}, ErrIdentityConflict
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET revision=revision+1,epoch=epoch+1 WHERE principal_type=? AND subject_id=? AND policy_mode='v2'`), command.SubjectType, command.SubjectID); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, command.SubjectType, command.SubjectID); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	receipt := AuthorizationChangeReceipt{ID: "change-" + key, ActorID: actor.PrincipalID, SubjectID: command.SubjectID, Revision: command.ExpectedRevision + 1, PlanDigest: plan.Digest, Reason: command.Reason, OccurredAt: s.clock().UTC(), Change: plan.Command}
	receipt.Change.Bindings = plan.ExpandedBindings
	receipt.Change.Grants = plan.ExpandedGrants
	receipt.Change.Assignments = plan.ExpandedAssignments
	receipt.Change.RevokeAssignmentIDs = mergePermissionRevocations(receipt.Change.RevokeAssignmentIDs, plan.AutomaticRevokeAssignmentIDs)
	receipt.Memberships = plan.ExpandedMemberships
	receipt.Change.RevokeBindingIDs = mergePermissionRevocations(receipt.Change.RevokeBindingIDs, plan.AutomaticRevokeBindingIDs)
	receipt.Change.RevokeGrantIDs = mergePermissionRevocations(receipt.Change.RevokeGrantIDs, plan.AutomaticRevokeGrantIDs)
	if err := s.authorizationChangeRecorder(ctx, tx, actor, receipt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), receipt.ID, actor.PrincipalID, command.SubjectID, key, requestDigest, string(encoded), receipt.OccurredAt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

func lockPermissionContinuity(ctx context.Context, tx *sql.Tx) error {
	var revision uint64
	return tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_continuity_guard WHERE id=1 FOR UPDATE`)).Scan(&revision)
}

func mergePermissionRevocations(explicit, automatic []string) []string {
	result := append([]string(nil), explicit...)
	for _, id := range automatic {
		if !slices.Contains(result, id) {
			result = append(result, id)
		}
	}
	return result
}

func insertRoleBinding(ctx context.Context, tx *sql.Tx, b RoleBinding) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	source, err := json.Marshal([]any{b.SubjectID, b.RoleCode, b.RoleVersion, b.Scope, b.SourceID})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload,source_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`), b.ID, b.SubjectID, b.RoleCode, b.RoleVersion, b.Scope.TenantID, b.Scope.DepartmentID, b.Scope.ApplicationID, b.Status, b.Revision, b.StartsAt, b.ExpiresAt, string(raw), permissionHash(source))
	if err != nil {
		return identityPersistenceError("create role binding", err)
	}
	return nil
}

func insertPermissionGrant(ctx context.Context, tx *sql.Tx, g Grant, now time.Time) error {
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at,permission_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), g.ID, g.TenantID, g.DepartmentID, g.ApplicationID, g.AgentInstanceID, g.SubjectType, g.SubjectID, g.Action, g.Effect, g.Status, g.Revision, grantKeyHash(g), now, string(raw))
	if err != nil {
		return identityPersistenceError("create resource grant", err)
	}
	return nil
}

func (s *SQLStore) SetPermissionResourceResolver(resolver AgentInstallationResolver) {
	s.permissionResourceResolver = resolver
}

// ResolvePermission verifies the organization facts before using the pure
// evaluator. Other modules consume this port rather than querying IAM tables.
func (s *SQLStore) ResolvePermission(ctx context.Context, kind PrincipalType, id string, query PermissionQuery) (PermissionDecision, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionDecision{}, err
	}
	defer tx.Rollback()
	if err := validatePermissionScope(ctx, tx, query.Scope); err != nil {
		return PermissionDecision{}, err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, kind, id)
	if err != nil {
		return PermissionDecision{}, err
	}
	query.Now = s.clock().UTC()
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil {
		return decision, err
	}
	return decision, tx.Commit()
}
