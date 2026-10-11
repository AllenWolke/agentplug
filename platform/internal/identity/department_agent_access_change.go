package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type DepartmentAgentChangeCommand struct {
	TenantID         string                       `json:"tenant_id"`
	DepartmentID     string                       `json:"department_id"`
	ExpectedRevision uint64                       `json:"expected_revision"`
	MigrateExisting  bool                         `json:"migrate_existing"`
	Entries          []DepartmentAgentPolicyEntry `json:"entries"`
	IdempotencyKey   string                       `json:"idempotency_key"`
	Reason           string                       `json:"reason"`
	PlanDigest       string                       `json:"plan_digest,omitempty"`
	PlanExpiresAt    time.Time                    `json:"plan_expires_at,omitempty"`
	StepUpToken      string                       `json:"step_up_token,omitempty"`
}

type DepartmentAgentChangeImpact struct {
	ActiveAllowRecords          uint64 `json:"active_allow_records"`
	PotentialRestrictedGrants   uint64 `json:"potential_restricted_grants"`
	PotentialRestrictedSubjects uint64 `json:"potential_restricted_subjects"`
	LegacySubjects              uint64 `json:"legacy_subjects"`
	Digest                      string `json:"digest"`
}

type DepartmentAgentChangePlan struct {
	Digest       string                       `json:"digest"`
	ExpiresAt    time.Time                    `json:"expires_at"`
	StepUpAction string                       `json:"step_up_action"`
	Command      DepartmentAgentChangeCommand `json:"change"`
	Before       DepartmentAgentPolicy        `json:"before"`
	After        DepartmentAgentPolicy        `json:"after"`
	Impact       DepartmentAgentChangeImpact  `json:"impact"`
}

type DepartmentAgentChangeReceipt struct {
	AdministrativeEvent
	RequestDigest string                       `json:"request_digest"`
	Command       DepartmentAgentChangeCommand `json:"change"`
	Policy        DepartmentAgentPolicy        `json:"policy"`
	Impact        DepartmentAgentChangeImpact  `json:"impact"`
}

func normalizeDepartmentAgentCommand(command DepartmentAgentChangeCommand) DepartmentAgentChangeCommand {
	command.Entries = normalizedDepartmentAgentEntries(command.Entries)
	for i := range command.Entries {
		command.Entries[i].ActionVersions = nil
	}
	command.StepUpToken = ""
	command.PlanDigest = ""
	command.PlanExpiresAt = time.Time{}
	return command
}

func DepartmentAgentChangeCommandDigest(command DepartmentAgentChangeCommand) (string, error) {
	raw, err := json.Marshal(struct {
		Domain  string
		Command DepartmentAgentChangeCommand
	}{"department-agent-policy/v1", normalizeDepartmentAgentCommand(command)})
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func validateDepartmentAgentCommand(command DepartmentAgentChangeCommand) error {
	if !validPermissionResourceID(command.TenantID) || !validPermissionResourceID(command.DepartmentID) || !validPermissionResourceID(command.IdempotencyKey) || strings.TrimSpace(command.Reason) == "" || len(command.Reason) > 1000 || len(command.Entries) > 256 || command.MigrateExisting != (command.ExpectedRevision == 0) || command.ExpectedRevision == math.MaxUint64 {
		return ErrInvalidResource
	}
	seen := map[string]bool{}
	for _, entry := range command.Entries {
		key := entry.ApplicationID + "\x00" + entry.InstallationID
		if seen[key] || validateDepartmentAgentEntry(entry) != nil {
			return ErrInvalidResource
		}
		seen[key] = true
	}
	return nil
}

func authorizeDepartmentAgentPolicy(owner PermissionSnapshot, actor sharedkernel.Scope, tenant, department string, now time.Time) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || owner.Mode != "v2" || owner.Principal.ID != actor.PrincipalID || owner.Principal.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	scope := ManagementScope{Type: "department", TenantID: tenant, DepartmentID: department}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "delegation.manage", Scope: scope, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	if companyAdministrationAllows(owner, scope, "delegation.manage", now) {
		return nil
	}
	for _, binding := range owner.Bindings {
		if binding.RoleCode == "super_admin" && binding.Scope.Type == "global" && slices.Contains(decision.BindingIDs, binding.ID) {
			return nil
		}
	}
	return ErrPermissionDenied
}

func equalPolicyTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

func nextDepartmentAgentPolicy(before DepartmentAgentPolicy, entries []DepartmentAgentPolicyEntry) DepartmentAgentPolicy {
	after := DepartmentAgentPolicy{TenantID: before.TenantID, DepartmentID: before.DepartmentID, Revision: before.Revision + 1, Entries: normalizedDepartmentAgentEntries(entries)}
	for i := range after.Entries {
		entry := &after.Entries[i]
		old := departmentAgentEntryFor(&before, entry.ApplicationID, entry.InstallationID)
		entry.ActionVersions = map[string]uint64{}
		for _, action := range entry.Actions {
			version := after.Revision
			if old != nil && equalPolicyTime(old.StartsAt, entry.StartsAt) && equalPolicyTime(old.ExpiresAt, entry.ExpiresAt) && old.ActionVersions[action] != 0 {
				version = old.ActionVersions[action]
			}
			entry.ActionVersions[action] = version
		}
	}
	after.EntriesDigest = departmentAgentEntriesDigest(after.Entries)
	return after
}

// Stream in subject order to count distinct affected subjects with constant
// memory. The digest includes every active allow and its current principal/mode
// facts, so a grant change after preview requires a new preview, even without a
// correctly maintained revision from an external migration.
func departmentAgentChangeImpact(ctx context.Context, reader permissionReader, after DepartmentAgentPolicy, now time.Time) (DepartmentAgentChangeImpact, error) {
	impact := DepartmentAgentChangeImpact{}
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT g.id,g.subject_type,g.subject_id,g.application_id,g.agent_instance_id,g.action,g.revision,g.permission_json,p.active,p.revision,COALESCE(m.policy_mode,'legacy'),COALESCE(m.revision,0),EXISTS(SELECT 1 FROM platform_identity_membership mm WHERE mm.subject_id=g.subject_id AND mm.tenant_id=g.tenant_id AND mm.department_id=g.department_id AND (mm.application_id='' OR mm.application_id=g.application_id) AND mm.status='active' AND (mm.starts_at IS NULL OR mm.starts_at<=?) AND (mm.expires_at IS NULL OR mm.expires_at>?)) FROM platform_identity_grant g JOIN platform_identity_principal p ON p.principal_type=g.subject_type AND p.id=g.subject_id LEFT JOIN platform_identity_policy_migration m ON m.principal_type=g.subject_type AND m.subject_id=g.subject_id WHERE g.tenant_id=? AND g.department_id=? AND g.effect='allow' AND g.status='active' ORDER BY g.subject_type,g.subject_id,g.id`), now, now, after.TenantID, after.DepartmentID)
	if err != nil {
		return impact, err
	}
	defer rows.Close()
	hash := sha256.New()
	previousAffected, previousLegacy := "", ""
	for rows.Next() {
		var grant Grant
		var raw []byte
		var active, departmentMember bool
		var principalRevision, modeRevision uint64
		var mode string
		if err := rows.Scan(&grant.ID, &grant.SubjectType, &grant.SubjectID, &grant.ApplicationID, &grant.AgentInstanceID, &grant.Action, &grant.Revision, &raw, &active, &principalRevision, &mode, &modeRevision, &departmentMember); err != nil {
			return impact, err
		}
		var metadata Grant
		if json.Unmarshal(raw, &metadata) != nil {
			return impact, ErrInvalidResource
		}
		grant.Validity = metadata.Validity
		grant.DepartmentAgentActionVersion = metadata.DepartmentAgentActionVersion
		encoded, err := json.Marshal([]any{grant, json.RawMessage(raw), active, principalRevision, mode, modeRevision, departmentMember})
		if err != nil {
			return impact, err
		}
		hash.Write(encoded)
		hash.Write([]byte{'\n'})
		impact.ActiveAllowRecords++
		if !active || grant.Action == "cancel" || grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
			continue
		}
		entry := departmentAgentEntryFor(&after, grant.ApplicationID, grant.AgentInstanceID)
		restricted := mode != "v2" || grant.SubjectType == PrincipalUser && !departmentMember || entry == nil || !slices.Contains(entry.Actions, grant.Action)
		if entry != nil {
			restricted = restricted || entry.ExpiresAt != nil && (grant.ExpiresAt == nil || grant.ExpiresAt.After(*entry.ExpiresAt)) || entry.StartsAt != nil && (grant.StartsAt == nil || grant.StartsAt.Before(*entry.StartsAt)) || grant.DepartmentAgentActionVersion != 0 && grant.DepartmentAgentActionVersion != entry.ActionVersions[grant.Action]
		}
		if restricted {
			impact.PotentialRestrictedGrants++
			key := string(grant.SubjectType) + "\x00" + grant.SubjectID
			if key != previousAffected {
				impact.PotentialRestrictedSubjects++
				previousAffected = key
			}
			if mode != "v2" && key != previousLegacy {
				impact.LegacySubjects++
				previousLegacy = key
			}
		}
	}
	impact.Digest = hex.EncodeToString(hash.Sum(nil))
	return impact, rows.Err()
}

func (s *SQLStore) planDepartmentAgentChange(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, command DepartmentAgentChangeCommand, deadline time.Time) (DepartmentAgentChangePlan, error) {
	command = normalizeDepartmentAgentCommand(command)
	if err := validateDepartmentAgentCommand(command); err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if err := authorizeDepartmentAgentPolicy(owner, actor, command.TenantID, command.DepartmentID, now); err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return DepartmentAgentChangePlan{}, ErrPermissionPlanStale
	}
	if err := validatePermissionScope(ctx, tx, ManagementScope{Type: "department", TenantID: command.TenantID, DepartmentID: command.DepartmentID}); err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	before, _, err := readDepartmentAgentPolicy(ctx, tx, command.TenantID, command.DepartmentID)
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	if before.Revision != command.ExpectedRevision {
		return DepartmentAgentChangePlan{}, ErrIdentityConflict
	}
	for _, entry := range command.Entries {
		if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
			return DepartmentAgentChangePlan{}, ErrInvalidResource
		}
		if err := validatePermissionScope(ctx, tx, ManagementScope{Type: "application", TenantID: command.TenantID, DepartmentID: command.DepartmentID, ApplicationID: entry.ApplicationID}); err != nil {
			return DepartmentAgentChangePlan{}, err
		}
		grant := Grant{TenantID: command.TenantID, DepartmentID: command.DepartmentID, ApplicationID: entry.ApplicationID, AgentInstanceID: entry.InstallationID, ResourceType: "agent_installation", ResourceID: entry.InstallationID, SubjectID: actor.PrincipalID, SubjectType: PrincipalUser}
		if err := s.validateGrantResource(ctx, grant); err != nil {
			return DepartmentAgentChangePlan{}, err
		}
	}
	after := nextDepartmentAgentPolicy(before, command.Entries)
	impact, err := departmentAgentChangeImpact(ctx, tx, after, now)
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	actorDigest, err := EffectivePermissionSnapshotDigest(owner, now)
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	raw, err := json.Marshal([]any{"department-agent-plan/v1", actorDigest, command, before, after, impact, deadline})
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	command.PlanDigest, command.PlanExpiresAt = permissionHash(raw), deadline
	return DepartmentAgentChangePlan{Digest: command.PlanDigest, ExpiresAt: deadline, StepUpAction: "delegation.manage", Command: command, Before: before, After: after, Impact: impact}, nil
}

func (s *SQLStore) PreviewDepartmentAgentChange(ctx context.Context, actor sharedkernel.Scope, command DepartmentAgentChangeCommand) (DepartmentAgentChangePlan, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return DepartmentAgentChangePlan{}, ErrPermissionDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DepartmentAgentChangePlan{}, err
	}
	defer tx.Rollback()
	plan, err := s.planDepartmentAgentChange(ctx, tx, actor, command, s.clock().UTC().Truncate(time.Microsecond).Add(5*time.Minute))
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit()
}

func (s *SQLStore) CommitDepartmentAgentChange(ctx context.Context, actor sharedkernel.Scope, command DepartmentAgentChangeCommand) (DepartmentAgentChangeReceipt, error) {
	if s.administrativeRecorder == nil {
		return DepartmentAgentChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return DepartmentAgentChangeReceipt{}, ErrPermissionDenied
	}
	if err := validateDepartmentAgentCommand(command); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	digest, err := DepartmentAgentChangeCommandDigest(command)
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	key := permissionHash([]byte("department-agent-change\x00" + actor.PrincipalID + "\x00" + command.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if err := authorizeDepartmentAgentPolicy(owner, actor, command.TenantID, command.DepartmentID, now); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	var priorDigest string
	var raw []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt_json FROM platform_identity_department_agent_change WHERE idempotency_key=? AND actor_id=?`), key, actor.PrincipalID).Scan(&priorDigest, &raw)
	if err == nil {
		if priorDigest != digest {
			return DepartmentAgentChangeReceipt{}, ErrIdentityConflict
		}
		var receipt DepartmentAgentChangeReceipt
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DepartmentAgentChangeReceipt{}, err
	}
	var departmentRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT d.revision FROM platform_identity_department d JOIN platform_identity_tenant t ON t.id=d.tenant_id WHERE d.id=? AND d.tenant_id=? AND d.status='active' AND t.status='active' FOR SHARE OF d,t`), command.DepartmentID, command.TenantID).Scan(&departmentRevision); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	plan, err := s.planDepartmentAgentChange(ctx, tx, actor, command, command.PlanExpiresAt)
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	if command.PlanDigest != plan.Digest {
		return DepartmentAgentChangeReceipt{}, ErrPermissionPlanStale
	}
	// Computing a large department's impact can take time. Recheck temporal
	// authority and proof expiry at the write boundary, not at transaction start.
	now = s.clock().UTC().Truncate(time.Microsecond)
	if !plan.ExpiresAt.After(now) {
		return DepartmentAgentChangeReceipt{}, ErrPermissionPlanStale
	}
	if err := authorizeDepartmentAgentPolicy(owner, actor, command.TenantID, command.DepartmentID, now); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	for _, entry := range plan.After.Entries {
		if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
			return DepartmentAgentChangeReceipt{}, ErrPermissionPlanStale
		}
	}
	if err := consumeStepUp(ctx, tx, actor, command.StepUpToken, "delegation.manage", plan.Digest, now); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	if err := persistDepartmentAgentPolicy(ctx, tx, plan.After, actor.PrincipalID, now); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	event := AdministrativeEvent{ID: "department-agent-change-" + key, ActorID: actor.PrincipalID, SubjectID: command.DepartmentID, Action: "department.agent_policy.change", Reason: command.Reason, Revision: plan.After.Revision, DetailsDigest: plan.Digest, OccurredAt: now}
	receipt := DepartmentAgentChangeReceipt{AdministrativeEvent: event, RequestDigest: digest, Command: plan.Command, Policy: plan.After, Impact: plan.Impact}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department_agent_change(idempotency_key,request_digest,actor_id,tenant_id,department_id,receipt_json,occurred_at) VALUES(?,?,?,?,?,?,?)`), key, digest, actor.PrincipalID, command.TenantID, command.DepartmentID, string(raw), now); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	return receipt, nil
}

func persistDepartmentAgentPolicy(ctx context.Context, tx *sql.Tx, policy DepartmentAgentPolicy, actor string, now time.Time) error {
	if policy.Revision == 1 {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department_agent_policy(tenant_id,department_id,revision,entries_digest,updated_by,updated_at) VALUES(?,?,?,?,?,?)`), policy.TenantID, policy.DepartmentID, policy.Revision, policy.EntriesDigest, actor, now); err != nil {
			return identityPersistenceError("create department Agent ceiling", err)
		}
	} else {
		result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_department_agent_policy SET revision=?,entries_digest=?,updated_by=?,updated_at=? WHERE tenant_id=? AND department_id=? AND revision=?`), policy.Revision, policy.EntriesDigest, actor, now, policy.TenantID, policy.DepartmentID, policy.Revision-1)
		if err != nil {
			return err
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return ErrIdentityConflict
		}
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_department_agent_entry WHERE tenant_id=? AND department_id=?`), policy.TenantID, policy.DepartmentID); err != nil {
		return err
	}
	for _, entry := range policy.Entries {
		actions, err := json.Marshal(entry.Actions)
		if err != nil {
			return err
		}
		versions, err := json.Marshal(entry.ActionVersions)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department_agent_entry(tenant_id,department_id,application_id,installation_id,actions_json,action_versions_json,starts_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`), policy.TenantID, policy.DepartmentID, entry.ApplicationID, entry.InstallationID, string(actions), string(versions), entry.StartsAt, entry.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}
