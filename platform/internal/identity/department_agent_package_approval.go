package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type AgentPackageApprovalItem struct {
	ApplicationID      string `json:"application_id"`
	InstallationID     string `json:"installation_id"`
	RequirementsDigest string `json:"requirements_digest"`
	ExpectedRevision   uint64 `json:"expected_revision"`
}

type AgentPackageApprovalCommand struct {
	Scope          ManagementScope            `json:"scope"`
	Items          []AgentPackageApprovalItem `json:"items"`
	Status         string                     `json:"status"`
	Reason         string                     `json:"reason"`
	IdempotencyKey string                     `json:"idempotency_key"`
	Validity
	PlanDigest    string    `json:"plan_digest,omitempty"`
	PlanExpiresAt time.Time `json:"plan_expires_at,omitempty"`
	StepUpToken   string    `json:"step_up_token,omitempty"`
}

type AgentPackageApprovalPlan struct {
	Command       AgentPackageApprovalCommand `json:"change"`
	Entries       []DepartmentAgentPackage    `json:"entries"`
	Digest        string                      `json:"plan_digest"`
	ExpiresAt     time.Time                   `json:"plan_expires_at"`
	RequestDigest string                      `json:"request_digest"`
	StepUpAction  string                      `json:"step_up_action"`
}

type AgentPackageApprovalReceipt struct {
	AdministrativeEvent
	Command AgentPackageApprovalCommand `json:"change"`
	Entries []DepartmentAgentPackage    `json:"entries"`
}

func agentPackageCommandDigest(c AgentPackageApprovalCommand) (string, error) {
	c.StepUpToken, c.PlanDigest = "", ""
	c.PlanExpiresAt = time.Time{}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return permissionHash(append([]byte("department-agent-package.approve\x00"), raw...)), nil
}

func (s *SQLStore) planAgentPackageApproval(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, c AgentPackageApprovalCommand, deadline time.Time) (AgentPackageApprovalPlan, error) {
	result := AgentPackageApprovalPlan{}
	// Preview must own nested selections and validity pointers, just like the
	// committing authorization planner. The caller may retain a retry command.
	rawCommand, err := json.Marshal(c)
	if err != nil {
		return result, err
	}
	var owned AgentPackageApprovalCommand
	if err := json.Unmarshal(rawCommand, &owned); err != nil {
		return result, err
	}
	c = owned
	if len(c.Items) < 1 || len(c.Items) > 16 || (c.Status != "active" && c.Status != "suspended") || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || c.Validity.Validate() != nil || c.Scope.Type != "department" || c.Scope.Validate() != nil {
		return result, ErrInvalidResource
	}
	now := s.clock().UTC()
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) || c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
		return result, ErrPermissionPlanStale
	}
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return result, err
	}
	if !canApproveDepartmentAgentPackage(owner, c.Scope, now) {
		return result, ErrPermissionDenied
	}
	if err := validatePermissionScope(ctx, tx, c.Scope); err != nil {
		return result, err
	}
	resolver, ok := s.capabilityResourceResolver.(AgentUseRequirementsResolver)
	if !ok {
		return result, ErrPermissionResourceResolverUnavailable
	}
	seen := map[string]bool{}
	for _, item := range c.Items {
		if !validPermissionResourceID(item.ApplicationID) || !validPermissionResourceID(item.InstallationID) || seen[item.InstallationID] {
			return result, ErrInvalidResource
		}
		seen[item.InstallationID] = true
		scope := ManagementScope{Type: "application", TenantID: c.Scope.TenantID, DepartmentID: c.Scope.DepartmentID, ApplicationID: item.ApplicationID}
		if err := validatePermissionScope(ctx, tx, scope); err != nil {
			return result, err
		}
		prior, err := readDepartmentAgentPackage(ctx, tx, scope, item.InstallationID)
		if err != nil {
			return result, err
		}
		revision := uint64(0)
		if prior != nil {
			revision = prior.Revision
		}
		if item.ExpectedRevision != revision || revision == ^uint64(0) {
			return result, ErrIdentityConflict
		}
		var requirements AgentUseRequirements
		if c.Status == "suspended" {
			if prior == nil {
				return result, ErrInvalidResource
			}
			requirements = prior.Requirements
		} else {
			requirements, err = resolver.ResolveAgentUseRequirements(ctx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, PrincipalType: "user", PrincipalID: actor.PrincipalID, InstallationID: item.InstallationID, AgentInstanceID: item.InstallationID})
			if err != nil {
				return result, err
			}
		}
		if requirements.InstallationID != item.InstallationID {
			return result, ErrInvalidResource
		}
		if err := requirements.Seal(); err != nil {
			return result, err
		}
		if requirements.Digest != item.RequirementsDigest {
			return result, ErrAgentPackageStale
		}
		result.Entries = append(result.Entries, DepartmentAgentPackage{ID: departmentAgentPackageID(scope, item.InstallationID), Scope: scope, InstallationID: item.InstallationID, Requirements: requirements, Status: c.Status, Revision: revision + 1, ApprovedBy: actor.PrincipalID, Reason: c.Reason, Validity: c.Validity})
	}
	c.StepUpToken, c.PlanDigest = "", ""
	c.PlanExpiresAt = time.Time{}
	result.Command, result.ExpiresAt, result.StepUpAction = c, deadline, "delegation.manage"
	result.RequestDigest, err = agentPackageCommandDigest(c)
	if err != nil {
		return result, err
	}
	actorDigest, err := PermissionSnapshotDigest(owner)
	if err != nil {
		return result, err
	}
	raw, err := json.Marshal(struct {
		Actor    string
		Command  AgentPackageApprovalCommand
		Entries  []DepartmentAgentPackage
		Deadline time.Time
	}{actorDigest, c, result.Entries, deadline})
	if err != nil {
		return result, err
	}
	result.Digest = permissionHash(raw)
	return result, nil
}

func (s *SQLStore) PreviewAgentPackageApproval(ctx context.Context, actor sharedkernel.Scope, c AgentPackageApprovalCommand) (AgentPackageApprovalPlan, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AgentPackageApprovalPlan{}, err
	}
	defer tx.Rollback()
	result, err := s.planAgentPackageApproval(ctx, tx, actor, c, s.clock().UTC().Add(5*time.Minute))
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (s *SQLStore) CommitAgentPackageApproval(ctx context.Context, actor sharedkernel.Scope, c AgentPackageApprovalCommand) (AgentPackageApprovalReceipt, error) {
	result := AgentPackageApprovalReceipt{}
	if s.administrativeRecorder == nil {
		return result, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 {
		return result, ErrInvalidResource
	}
	digest, err := agentPackageCommandDigest(c)
	if err != nil {
		return result, err
	}
	key := permissionHash([]byte("department-agent-package.approve\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return result, err
	}
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return result, err
	}
	if err := requireSuperAdministrator(owner, "delegation.manage", s.clock().UTC()); err != nil {
		return result, err
	}
	var previousDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&previousDigest, &saved)
	if err == nil {
		if previousDigest != digest {
			return result, ErrIdentityConflict
		}
		err = json.Unmarshal(saved, &result)
		return result, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	plan, err := s.planAgentPackageApproval(ctx, tx, actor, c, c.PlanExpiresAt)
	if err != nil {
		return result, err
	}
	if c.PlanDigest != plan.Digest || c.PlanDigest == "" {
		return result, ErrPermissionPlanStale
	}
	now := s.clock().UTC()
	if err := consumeStepUp(ctx, tx, actor, c.StepUpToken, "delegation.manage", digest, now); err != nil {
		return result, err
	}
	for index := range plan.Entries {
		entry := &plan.Entries[index]
		entry.UpdatedAt = now
		raw, err := json.Marshal(entry)
		if err != nil {
			return result, err
		}
		if entry.Revision == 1 {
			_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department_agent_package(id,tenant_id,department_id,application_id,installation_id,status,revision,payload,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`), entry.ID, entry.Scope.TenantID, entry.Scope.DepartmentID, entry.Scope.ApplicationID, entry.InstallationID, entry.Status, entry.Revision, string(raw), now)
		} else {
			var changed sql.Result
			changed, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_department_agent_package SET status=?,revision=?,payload=?,updated_at=? WHERE id=? AND revision=?`), entry.Status, entry.Revision, string(raw), now, entry.ID, entry.Revision-1)
			if err == nil {
				count, readErr := changed.RowsAffected()
				if readErr != nil {
					return result, readErr
				}
				if count != 1 {
					return result, ErrIdentityConflict
				}
			}
		}
		if err != nil {
			return result, err
		}
	}
	// The subject is a department, not a user whose IAM revision changed.
	// Runtime authorization fingerprints include referenced approvals, so their
	// suspension is observed without fabricating a principal invalidation event.
	result = AgentPackageApprovalReceipt{AdministrativeEvent: AdministrativeEvent{DetailsDigest: digest, ID: "agent-package-approval-" + key, ActorID: actor.PrincipalID, SubjectID: c.Scope.DepartmentID, Action: "identity.department_agent_package.approved", Reason: c.Reason, Revision: 1, OccurredAt: now}, Command: plan.Command, Entries: plan.Entries}
	if c.Status == "suspended" {
		result.Action = "identity.department_agent_package.suspended"
	}
	auditScope := actor
	auditScope.TenantID, auditScope.DepartmentID, auditScope.ApplicationID = c.Scope.TenantID, c.Scope.DepartmentID, plan.Entries[0].Scope.ApplicationID
	if err := s.administrativeRecorder(ctx, tx, auditScope, result.AdministrativeEvent); err != nil {
		return result, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), result.ID, actor.PrincipalID, c.Scope.DepartmentID, key, digest, string(raw), now); err != nil {
		return result, err
	}
	return result, tx.Commit()
}
