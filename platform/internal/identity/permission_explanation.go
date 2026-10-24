package identity

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type PermissionExplanation struct {
	PermissionDecision
	SubjectID       string          `json:"subject_id"`
	SubjectType     PrincipalType   `json:"subject_type"`
	Action          string          `json:"action"`
	Scope           ManagementScope `json:"scope"`
	ResourceType    string          `json:"resource_type,omitempty"`
	ResourceID      string          `json:"resource_id,omitempty"`
	ObjectID        string          `json:"object_id,omitempty"`
	ComputedAt      time.Time       `json:"computed_at"`
	SubjectRevision uint64          `json:"subject_revision,string"`
	// This is a diagnostic snapshot version, not an execution capability epoch.
	EffectiveVersion string `json:"effective_permission_version"`
	// Null for denied/management/history decisions without an execution epoch.
	AuthorizationEpoch *uint64       `json:"authorization_epoch"`
	AgentID            string        `json:"agent_id,omitempty"`
	AgentVersionID     string        `json:"agent_version_id,omitempty"`
	Bindings           []RoleBinding `json:"matched_role_bindings"`
	Grants             []Grant       `json:"matched_resource_grants"`
	DelegationIDs      []string      `json:"matched_delegation_ids"`
	Delegations        []Delegation  `json:"matched_delegations"`
	DiagnosticReasons  []string      `json:"diagnostic_reasons"`
}

var ErrPermissionExplanationStale = errors.New("permission explanation snapshot changed")

type PermissionExplanationRepository interface {
	ExplainPermission(context.Context, sharedkernel.Scope, PrincipalType, string, PermissionQuery) (PermissionExplanation, error)
}

func explainPermissionSnapshot(snapshot PermissionSnapshot, query PermissionQuery) (PermissionExplanation, error) {
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil {
		return PermissionExplanation{}, err
	}
	switch query.Action {
	case "authorization.change", "access_request.decide", "principal.disable", "membership.manage":
		available, e := managementCapabilityAvailable(snapshot, query)
		if e != nil {
			return PermissionExplanation{}, e
		}
		if !available && decision.Allowed {
			decision.Allowed, decision.Reason = false, "DELEGATION_REQUIRED"
		} else if !available && query.Action == "membership.manage" {
			qualification := query
			qualification.Action = "authorization.change"
			base, e := EvaluatePermission(snapshot, qualification)
			if e != nil {
				return PermissionExplanation{}, e
			}
			if base.Allowed && slices.ContainsFunc(snapshot.Bindings, func(b RoleBinding) bool {
				return b.RoleCode == "permission_admin" && slices.Contains(base.BindingIDs, b.ID)
			}) {
				decision = base
				decision.Allowed, decision.Reason = false, "DELEGATION_REQUIRED"
			}
		} else if available && !decision.Allowed {
			qualification := query
			qualification.Action = "authorization.change"
			decision, e = EvaluatePermission(snapshot, qualification)
			if e != nil {
				return PermissionExplanation{}, e
			}
			decision.Allowed, decision.Reason = true, "DELEGATED_MANAGEMENT"
		}
	}
	if query.Object != nil && decision.Reason == "RESOURCE_GRANT_REQUIRED" {
		qualification := query
		qualification.Object = nil
		base, e := EvaluatePermission(snapshot, qualification)
		if e != nil {
			return PermissionExplanation{}, e
		}
		if base.Allowed {
			decision.Reason = "DATA_SCOPE_MISMATCH"
		}
	}
	digest, err := EffectivePermissionSnapshotDigest(snapshot, query.Now)
	if err != nil {
		return PermissionExplanation{}, err
	}
	out := PermissionExplanation{PermissionDecision: decision, SubjectID: snapshot.Principal.ID, SubjectType: snapshot.Principal.Type,
		Action: query.Action, Scope: query.Scope, ResourceType: query.ResourceType, ResourceID: query.ResourceID, ComputedAt: query.Now,
		SubjectRevision: snapshot.Principal.Revision, EffectiveVersion: digest, Bindings: []RoleBinding{}, Grants: []Grant{}, DelegationIDs: []string{}, Delegations: []Delegation{}, DiagnosticReasons: []string{}}
	add := func(reason string) {
		if !slices.Contains(out.DiagnosticReasons, reason) {
			out.DiagnosticReasons = append(out.DiagnosticReasons, reason)
		}
	}
	member := false
	for _, m := range snapshot.Memberships {
		if m.SubjectID != snapshot.Principal.ID || !m.Scope.Contains(query.Scope) {
			continue
		}
		if m.Status == "active" && m.Effective(query.Now) {
			member = true
		}
		if m.Status != "active" {
			add("MEMBERSHIP_INACTIVE")
		} else if m.StartsAt != nil && query.Now.Before(*m.StartsAt) {
			add("MEMBERSHIP_NOT_STARTED")
		} else if m.ExpiresAt != nil && !query.Now.Before(*m.ExpiresAt) {
			add("MEMBERSHIP_EXPIRED")
		}
	}
	for _, b := range snapshot.Bindings {
		if b.SubjectID != snapshot.Principal.ID || !b.Scope.Contains(query.Scope) {
			continue
		}
		eligible := false
		for _, role := range snapshot.Roles {
			if role.Code == b.RoleCode && role.Version == b.RoleVersion && slices.Contains(role.ScopeTypes, b.Scope.Type) &&
				(slices.Contains(role.Actions, query.Action) || query.Action == "membership.manage" && role.Code == "permission_admin" && slices.Contains(role.Actions, "authorization.change")) {
				eligible = true
			}
		}
		if !eligible {
			continue
		}
		if b.Status != "active" {
			add("ROLE_INACTIVE")
			continue
		}
		if !b.Effective(query.Now) {
			if b.StartsAt != nil && query.Now.Before(*b.StartsAt) {
				add("ROLE_NOT_STARTED")
			} else {
				add("ROLE_EXPIRED")
			}
			continue
		}
		if member || b.Scope.Type == "global" && slices.Contains(decision.BindingIDs, b.ID) {
			out.Bindings = append(out.Bindings, b)
		}
	}
	for _, g := range snapshot.Grants {
		if g.SubjectType != snapshot.Principal.Type || g.SubjectID != snapshot.Principal.ID || g.Action != query.Action || g.ResourceType != query.ResourceType || g.ResourceID != query.ResourceID {
			continue
		}
		if !(ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}).Contains(query.Scope) {
			continue
		}
		if g.ResourceType != "agent_installation" && query.Scope.Type == "agent_installation" && g.AgentInstanceID != query.Scope.ResourceID {
			continue
		}
		if g.ResourceType == "agent_installation" && g.AgentInstanceID != query.ResourceID {
			continue
		}
		if !explanationGrantMatchesObject(snapshot, query, g) {
			continue
		}
		if g.Status != "active" {
			add("GRANT_INACTIVE")
			continue
		}
		if !g.Effective(query.Now) {
			if g.StartsAt != nil && query.Now.Before(*g.StartsAt) {
				add("GRANT_NOT_STARTED")
			} else {
				add("GRANT_EXPIRED")
			}
			continue
		}
		if !agentPackageAllowsGrant(snapshot, g, query.Now) || hasAgentPackageStamp(g) && (query.RequirePublishedVersion && query.PublishedAgentVersionID == "" || query.PublishedAgentVersionID != "" && !agentPackageMatchesVersion(snapshot, g, query.PublishedAgentVersionID)) {
			continue
		}
		out.Grants = append(out.Grants, g)
	}
	for _, b := range out.Bindings {
		if b.DelegationID != "" && !slices.Contains(out.DelegationIDs, b.DelegationID) {
			out.DelegationIDs = append(out.DelegationIDs, b.DelegationID)
		}
	}
	for _, g := range out.Grants {
		if g.DelegationID != "" && !slices.Contains(out.DelegationIDs, g.DelegationID) {
			out.DelegationIDs = append(out.DelegationIDs, g.DelegationID)
		}
	}
	if slices.ContainsFunc(out.Bindings, func(b RoleBinding) bool {
		return b.RoleCode == "permission_admin" || b.RoleCode == "department_admin" && b.RoleVersion == 2
	}) {
		for _, delegation := range snapshot.Delegations {
			if delegation.SubjectID != snapshot.Principal.ID || !delegation.Scope.Contains(query.Scope) || !slices.Contains(delegation.ManagementActions, query.Action) {
				continue
			}
			if delegation.Status != "active" {
				add("DELEGATION_INACTIVE")
			} else if delegation.StartsAt != nil && query.Now.Before(*delegation.StartsAt) {
				add("DELEGATION_NOT_STARTED")
			} else if delegation.ExpiresAt != nil && !query.Now.Before(*delegation.ExpiresAt) {
				add("DELEGATION_EXPIRED")
			} else {
				out.Delegations = append(out.Delegations, delegation)
				if !slices.Contains(out.DelegationIDs, delegation.ID) {
					out.DelegationIDs = append(out.DelegationIDs, delegation.ID)
				}
			}
		}
	}
	if !decision.Allowed {
		add(decision.Reason)
	}
	return out, nil
}

// Actor scope and the target explanation use one repeatable-read transaction.
// Client-provided object facts never enter this diagnostic interface.
func (s *SQLStore) ExplainPermission(ctx context.Context, actor sharedkernel.Scope, kind PrincipalType, subject string, query PermissionQuery) (PermissionExplanation, error) {
	return s.explainPermission(ctx, actor, kind, subject, query, "")
}

func (s *SQLStore) explainPermission(ctx context.Context, actor sharedkernel.Scope, kind PrincipalType, subject string, query PermissionQuery, objectID string) (PermissionExplanation, error) {
	if s == nil || s.db == nil || actor.PrincipalID == "" || actor.PrincipalType != string(PrincipalUser) || subject == "" || query.Object != nil || query.Scope.Validate() != nil || kind != PrincipalUser && kind != PrincipalServicePrincipal {
		return PermissionExplanation{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionExplanation{}, err
	}
	defer tx.Rollback()
	now := s.clock().UTC()
	var owner PermissionSnapshot
	other := kind != PrincipalUser || subject != actor.PrincipalID
	if other {
		owner, err = loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			return PermissionExplanation{}, err
		}
		if owner.Principal.TenantID != actor.TenantID {
			return PermissionExplanation{}, ErrPermissionDenied
		}
		read, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.read", Scope: query.Scope, Now: now})
		if err != nil {
			return PermissionExplanation{}, err
		}
		if !read.Allowed {
			return PermissionExplanation{}, ErrPermissionDenied
		}
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, kind, subject)
	if err != nil {
		return PermissionExplanation{}, err
	}
	if query.Scope.Type != "global" && snapshot.Principal.TenantID != query.Scope.TenantID {
		return PermissionExplanation{}, ErrPrincipalNotFound
	}
	if kind == PrincipalUser && subject == actor.PrincipalID && snapshot.Principal.TenantID != actor.TenantID {
		return PermissionExplanation{}, ErrPermissionDenied
	}
	if !other {
		current := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
		visible := current.Contains(query.Scope)
		for _, member := range snapshot.Memberships {
			if member.Scope.Contains(query.Scope) {
				visible = true
			}
		}
		if !visible {
			read, e := EvaluatePermission(snapshot, PermissionQuery{Action: "authorization.read", Scope: query.Scope, Now: now})
			if e != nil {
				return PermissionExplanation{}, e
			}
			visible = read.Allowed
		}
		if !visible {
			return PermissionExplanation{}, ErrPermissionDenied
		}
	}
	if err = validatePermissionScope(ctx, tx, query.Scope); err != nil {
		return PermissionExplanation{}, err
	}
	if other && query.Scope.Type != "global" {
		visible := false
		for _, member := range snapshot.Memberships {
			if member.Scope.Contains(query.Scope) || query.Scope.Contains(member.Scope) {
				visible = true
			}
		}
		for _, grant := range snapshot.Grants {
			scope := grantAuthorizationScope(grant)
			if scope.Contains(query.Scope) || query.Scope.Contains(scope) {
				visible = true
			}
		}
		if !visible {
			return PermissionExplanation{}, ErrPrincipalNotFound
		}
	}
	if err = s.validateExplanationResource(ctx, snapshot.Principal, query); err != nil {
		return PermissionExplanation{}, err
	}
	query.Now = now
	if err = s.bindAgentPackagePublishedVersion(ctx, snapshot, &query); err != nil {
		return PermissionExplanation{}, err
	}
	if objectID != "" {
		viewer := snapshot
		if other {
			viewer = owner
		}
		object, e := s.resolveExplanationObject(ctx, actor, viewer, query, objectID)
		if e != nil {
			return PermissionExplanation{}, e
		}
		query.Object = &object
	}
	out, err := explainPermissionSnapshot(snapshot, query)
	if err != nil {
		return PermissionExplanation{}, err
	}
	out.ObjectID = objectID
	// Preserve an IAM denial as the primary reason. Even when IAM allows the
	// action, a draft/disabled Catalog resource cannot be reported runnable.
	if out.Allowed {
		reason, e := s.explanationRunBlockReason(ctx, snapshot.Principal, query)
		if e != nil {
			return PermissionExplanation{}, e
		}
		if reason != "" {
			out.Allowed = false
			out.Reason = reason
			out.DiagnosticReasons = append(out.DiagnosticReasons, reason)
		}
	}
	if other {
		readable := func(scope ManagementScope) (bool, error) {
			d, e := EvaluatePermission(owner, PermissionQuery{Action: "authorization.read", Scope: scope, Now: now})
			return d.Allowed, e
		}
		bindings := []RoleBinding{}
		for _, binding := range out.Bindings {
			ok, e := readable(binding.Scope)
			if e != nil {
				return PermissionExplanation{}, e
			}
			if ok {
				bindings = append(bindings, binding)
			}
		}
		out.Bindings = bindings
		delegations := []Delegation{}
		for _, delegation := range out.Delegations {
			ok, e := readable(delegation.Scope)
			if e != nil {
				return PermissionExplanation{}, e
			}
			if ok {
				delegations = append(delegations, delegation)
			}
		}
		out.Delegations = delegations
		out.BindingIDs = slices.DeleteFunc(out.BindingIDs, func(id string) bool {
			return !slices.ContainsFunc(bindings, func(b RoleBinding) bool { return b.ID == id })
		})
		// Delegation source IDs must not disclose sources hidden by scope redaction.
		out.DelegationIDs = []string{}
		for _, b := range out.Bindings {
			if b.DelegationID != "" && !slices.Contains(out.DelegationIDs, b.DelegationID) {
				out.DelegationIDs = append(out.DelegationIDs, b.DelegationID)
			}
		}
		for _, g := range out.Grants {
			if g.DelegationID != "" && !slices.Contains(out.DelegationIDs, g.DelegationID) {
				out.DelegationIDs = append(out.DelegationIDs, g.DelegationID)
			}
		}
		for _, delegation := range out.Delegations {
			if !slices.Contains(out.DelegationIDs, delegation.ID) {
				out.DelegationIDs = append(out.DelegationIDs, delegation.ID)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return PermissionExplanation{}, err
	}
	if out.Allowed && query.Action == "run" {
		executionScope, e := s.explanationExecutionScope(ctx, snapshot.Principal, query)
		if e != nil {
			return PermissionExplanation{}, e
		}
		epoch, e := s.currentAuthorizationEpoch(ctx, executionScope, query.Action, out.EffectiveVersion)
		if e != nil {
			return PermissionExplanation{}, e
		}
		out.AuthorizationEpoch = &epoch
		out.AgentID, out.AgentVersionID = executionScope.AgentID, executionScope.AgentVersionID
	}
	return out, nil
}

var _ PermissionExplanationRepository = (*SQLStore)(nil)
