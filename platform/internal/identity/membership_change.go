package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type MembershipMutation struct {
	ID               string          `json:"id"`
	Scope            ManagementScope `json:"scope"`
	ExpectedRevision uint64          `json:"expected_revision"`
	Status           string          `json:"status"`
	Validity
}

func membershipCovers(members []Membership, subject string, scope ManagementScope, now time.Time) bool {
	for _, m := range members {
		if m.SubjectID == subject && m.Status == "active" && m.Effective(now) && m.Scope.Contains(scope) {
			return true
		}
	}
	return false
}

func authorizeMembershipMutation(owner, target PermissionSnapshot, actor sharedkernel.Scope, scope ManagementScope, validity Validity, now time.Time) (string, error) {
	direct, err := EvaluatePermission(owner, PermissionQuery{Action: "membership.manage", Scope: scope, Now: now})
	if err != nil {
		return "", err
	}
	super := false
	for _, b := range owner.Bindings {
		if b.RoleCode == "super_admin" && slices.Contains(direct.BindingIDs, b.ID) {
			super = true
		}
	}
	if super {
		return "", nil
	}
	if actor.PrincipalID == target.Principal.ID {
		return "", ErrPermissionDenied
	}
	for _, b := range target.Bindings {
		if b.Status == "active" && protectedAdministratorBinding(b) {
			return "", ErrPermissionDenied
		}
		if administrationKind(owner, now) == "department" && b.SubjectID == target.Principal.ID && b.Status == "active" && b.Effective(now) && b.RoleCode == "department_admin" && b.Scope.Contains(scope) {
			return "", ErrPermissionDenied
		}
	}
	if direct.Allowed {
		return "", nil
	}
	// Permission administrators obtain member-making authority only from an
	// explicit delegation; ordinary organization admins use their scoped role.
	qualification, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.change", Scope: scope, Now: now})
	if err != nil {
		return "", err
	}
	qualified := false
	for _, b := range owner.Bindings {
		if b.RoleCode == "permission_admin" && slices.Contains(qualification.BindingIDs, b.ID) {
			qualified = true
		}
	}
	if !qualification.Allowed || !qualified {
		return "", ErrPermissionDenied
	}
	for _, d := range owner.Delegations {
		if d.Covers(actor.PrincipalID, "membership.manage", "", "", "", scope, DataScope{}, validity, now) {
			return d.ID, nil
		}
	}
	return "", ErrPermissionDenied
}

// Compute member changes and their dependent revocations against one snapshot.
// Removing the last membership revokes latent allows so rejoining later cannot
// silently restore old business authority. Explicit denies are never deleted.
func planMembershipMutations(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, owner, target PermissionSnapshot, command AuthorizationChangeCommand, now time.Time) ([]Membership, []Membership, []string, []string, error) {
	projected := append([]Membership(nil), target.Memberships...)
	changes := []Membership{}
	changed := map[string]Membership{}
	reactivated := map[string]bool{}
	if len(command.Memberships) > 0 && command.SubjectType != PrincipalUser {
		return nil, nil, nil, nil, ErrInvalidResource
	}
	seen := map[string]bool{}
	for _, mutation := range command.Memberships {
		if mutation.ID == "" || len(mutation.ID) > 128 || strings.TrimSpace(mutation.ID) != mutation.ID || strings.ContainsAny(mutation.ID, "*\x00") || seen[mutation.ID] || mutation.Scope.Validate() != nil || !slices.Contains([]string{"tenant", "department", "application"}, mutation.Scope.Type) || mutation.Scope.TenantID != target.Principal.TenantID || mutation.Validity.Validate() != nil || (mutation.Status != "active" && mutation.Status != "revoked") || (mutation.Status == "active" && mutation.ExpiresAt != nil && !mutation.ExpiresAt.After(now)) {
			return nil, nil, nil, nil, ErrInvalidResource
		}
		seen[mutation.ID] = true
		if err := validatePermissionScope(ctx, tx, mutation.Scope); err != nil {
			return nil, nil, nil, nil, err
		}
		delegation, err := authorizeMembershipMutation(owner, target, actor, mutation.Scope, mutation.Validity, now)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		index := -1
		for i, m := range projected {
			if m.ID == mutation.ID {
				index = i
				break
			}
			if m.Scope == mutation.Scope {
				return nil, nil, nil, nil, ErrIdentityConflict
			}
		}
		member := Membership{ID: mutation.ID, SubjectID: command.SubjectID, Scope: mutation.Scope, Validity: mutation.Validity, Status: mutation.Status, Revision: 1, SourceID: "membership:" + command.IdempotencyKey, DelegationID: delegation}
		if index < 0 {
			if mutation.ExpectedRevision != 0 || mutation.Status != "active" {
				return nil, nil, nil, nil, ErrIdentityConflict
			}
			projected = append(projected, member)
		} else {
			prior := projected[index]
			if prior.Revision != mutation.ExpectedRevision || prior.Scope != mutation.Scope || prior.SubjectID != command.SubjectID {
				return nil, nil, nil, nil, ErrIdentityConflict
			}
			member.Revision = prior.Revision + 1
			if prior.Revision == ^uint64(0) {
				return nil, nil, nil, nil, ErrIdentityConflict
			}
			reactivated[prior.ID] = mutation.Status == "active" && !prior.Effective(now) || mutation.Status == "active" && prior.Status != "active"
			changed[prior.ID] = prior
			projected[index] = member
		}
		changes = append(changes, member)
	}
	preservedCoverage := func(scope ManagementScope) bool {
		for _, m := range projected {
			if reactivated[m.ID] {
				continue
			}
			if membershipCovers([]Membership{m}, command.SubjectID, scope, now) {
				return true
			}
		}
		return false
	}
	affected := func(scope ManagementScope) bool {
		for _, m := range changed {
			if m.Scope.Contains(scope) {
				return true
			}
		}
		return false
	}
	bindings, grants := []string{}, []string{}
	for _, b := range target.Bindings {
		if b.Status != "active" || !affected(b.Scope) {
			continue
		}
		if protectedAdministratorBinding(b) {
			if membershipCovers(target.Memberships, command.SubjectID, b.Scope, now) != membershipCovers(projected, command.SubjectID, b.Scope, now) {
				return nil, nil, nil, nil, ErrPermissionDenied
			}
			continue
		}
		if !preservedCoverage(b.Scope) {
			bindings = append(bindings, b.ID)
		}
	}
	for _, g := range target.Grants {
		scope := ManagementScope{Type: "application", TenantID: g.TenantID, DepartmentID: g.DepartmentID, ApplicationID: g.ApplicationID}
		if g.Status == "active" && g.Effect == "allow" && affected(scope) && !preservedCoverage(scope) {
			grants = append(grants, g.ID)
		}
	}
	return projected, changes, bindings, grants, nil
}

func persistMembershipMutation(ctx context.Context, tx *sql.Tx, m Membership, expected uint64) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if expected == 0 {
		key, _ := json.Marshal([]any{m.SubjectID, m.Scope})
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload,scope_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), m.ID, m.SubjectID, m.Scope.TenantID, m.Scope.DepartmentID, m.Scope.ApplicationID, m.Status, m.Revision, m.StartsAt, m.ExpiresAt, string(raw), permissionHash(key))
		if err != nil {
			return identityPersistenceError("create membership", err)
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_membership SET status=?,revision=?,starts_at=?,expires_at=?,payload=? WHERE id=? AND subject_id=? AND revision=?`), m.Status, m.Revision, m.StartsAt, m.ExpiresAt, string(raw), m.ID, m.SubjectID, expected)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrIdentityConflict
	}
	return nil
}
