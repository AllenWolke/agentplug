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

const taskAssignmentDDL = `CREATE TABLE IF NOT EXISTS platform_identity_task_assignment (
	id VARCHAR(128) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,task_id VARCHAR(128) NOT NULL,action VARCHAR(64) NOT NULL,
	tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,agent_instance_id VARCHAR(128) NOT NULL,
	status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,starts_at TIMESTAMPTZ(6) NULL,expires_at TIMESTAMPTZ(6) NULL,payload JSON NOT NULL,source_hash VARCHAR(64) NOT NULL,
	CONSTRAINT uq_task_assignment_source UNIQUE(source_hash));
CREATE INDEX IF NOT EXISTS idx_task_assignment_subject ON platform_identity_task_assignment (subject_id,status);
CREATE INDEX IF NOT EXISTS idx_task_assignment_task ON platform_identity_task_assignment (tenant_id,department_id,application_id,agent_instance_id,task_id,status);`

func (s *SQLStore) EnsureTaskAssignmentSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(taskAssignmentDDL))
	return err
}

func (s *SQLStore) SetPermissionTaskResolver(resolver PermissionTaskResolver) {
	s.permissionTaskResolver = resolver
}

func loadTaskAssignments(ctx context.Context, reader permissionReader, subject string) ([]TaskAssignment, error) {
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT id,subject_id,task_id,action,tenant_id,department_id,application_id,agent_instance_id,status,revision,payload FROM platform_identity_task_assignment WHERE subject_id=? ORDER BY id`), subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []TaskAssignment{}
	for rows.Next() {
		var assignment TaskAssignment
		var raw []byte
		assignment.Scope.Type = "agent_installation"
		if err := rows.Scan(&assignment.ID, &assignment.SubjectID, &assignment.TaskID, &assignment.Action, &assignment.Scope.TenantID, &assignment.Scope.DepartmentID, &assignment.Scope.ApplicationID, &assignment.Scope.ResourceID, &assignment.Status, &assignment.Revision, &raw); err != nil {
			return nil, err
		}
		var metadata TaskAssignment
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, err
		}
		assignment.Validity, assignment.SourceID, assignment.DelegationID, assignment.TaskObject = metadata.Validity, metadata.SourceID, metadata.DelegationID, metadata.TaskObject
		result = append(result, assignment)
	}
	return result, rows.Err()
}

func insertTaskAssignment(ctx context.Context, tx *sql.Tx, assignment TaskAssignment) error {
	raw, err := json.Marshal(assignment)
	if err != nil {
		return err
	}
	key, err := json.Marshal([]any{assignment.SubjectID, assignment.TaskID, assignment.Action, assignment.Scope, assignment.SourceID})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_task_assignment(id,subject_id,task_id,action,tenant_id,department_id,application_id,agent_instance_id,status,revision,starts_at,expires_at,payload,source_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), assignment.ID, assignment.SubjectID, assignment.TaskID, assignment.Action, assignment.Scope.TenantID, assignment.Scope.DepartmentID, assignment.Scope.ApplicationID, assignment.Scope.ResourceID, assignment.Status, assignment.Revision, assignment.StartsAt, assignment.ExpiresAt, string(raw), permissionHash(key))
	if err != nil {
		return identityPersistenceError("create task assignment", err)
	}
	return nil
}

func automaticAssignmentRevocations(target PermissionSnapshot, command AuthorizationChangeCommand, projected []Membership, now time.Time) []string {
	result := []string{}
	preserved := []Membership{}
	for _, member := range projected {
		reactivated := false
		for _, mutation := range command.Memberships {
			if mutation.ID != member.ID || mutation.Status != "active" {
				continue
			}
			for _, previous := range target.Memberships {
				if previous.ID == member.ID && (previous.Status != "active" || !previous.Effective(now)) {
					reactivated = true
				}
			}
		}
		if !reactivated {
			preserved = append(preserved, member)
		}
	}
	for _, assignment := range target.Assignments {
		if assignment.Status != "active" {
			continue
		}
		affected := false
		for _, mutation := range command.Memberships {
			for _, previous := range target.Memberships {
				if previous.ID == mutation.ID && previous.Scope.Contains(assignment.Scope) {
					affected = true
				}
			}
		}
		if removedDepartmentContains(command, assignment.Scope) || affected && !membershipCovers(preserved, target.Principal.ID, assignment.Scope, now) {
			result = append(result, assignment.ID)
		}
	}
	return result
}

type assignmentScopeCheck func(ManagementScope) error
type assignmentAuthorize func(ManagementScope, string, string, string, DataScope, Validity) (string, error)

func (s *SQLStore) planTaskAssignmentChanges(ctx context.Context, actor sharedkernel.Scope, target PermissionSnapshot, command *AuthorizationChangeCommand, automatic []string, seen map[string]bool, check assignmentScopeCheck, authorize assignmentAuthorize) error {
	if (len(command.Assignments) != 0 || len(command.RevokeAssignmentIDs) != 0) && command.SubjectType != PrincipalUser {
		return ErrInvalidResource
	}
	for index := range command.Assignments {
		assignment := &command.Assignments[index]
		if assignment.ID == "" || len(assignment.ID) > 128 || seen[assignment.ID] || assignment.SubjectID != command.SubjectID || assignment.TaskID == "" || len(assignment.TaskID) > 128 || strings.TrimSpace(assignment.TaskID) != assignment.TaskID || strings.ContainsAny(assignment.TaskID, "*\x00") || assignment.Scope.Type != "agent_installation" || assignment.Scope.Validate() != nil || assignment.Status != "active" || assignment.Revision != 1 || assignment.SourceID == "" || assignment.TaskObject != nil || assignment.Validity.Validate() != nil {
			return ErrInvalidResource
		}
		seen[assignment.ID] = true
		known := false
		for _, action := range BuiltinPermissionActions() {
			if !action.Management && action.Code == assignment.Action && action.ResourceType == "agent_installation" {
				known = true
			}
		}
		if !known {
			return ErrInvalidResource
		}
		application := assignment.Scope
		application.Type, application.ResourceID = "application", ""
		if err := check(application); err != nil {
			return err
		}
		data := DataScope{Type: "explicit_set", IDs: []string{assignment.TaskID}}
		delegation, err := authorize(assignment.Scope, "", assignment.Action, assignment.Scope.ResourceID, data, assignment.Validity)
		if err != nil {
			return err
		}
		if s.permissionTaskResolver == nil {
			return ErrInvalidResource
		}
		object, err := s.permissionTaskResolver.ResolvePermissionTask(ctx, actor, assignment.Scope, assignment.TaskID)
		if err != nil {
			return err
		}
		if object.ID != assignment.TaskID || object.Scope != assignment.Scope || object.OwnerID == "" {
			return ErrInvalidResource
		}
		object = canonicalAssignmentObject(object)
		assignment.TaskObject, assignment.DelegationID = &object, delegation
	}
	for _, id := range command.RevokeAssignmentIDs {
		if id == "" || seen[id] {
			return ErrInvalidResource
		}
		seen[id] = true
		found := false
		for _, assignment := range target.Assignments {
			if assignment.ID != id || assignment.Status != "active" {
				continue
			}
			found = true
			_, err := authorize(assignment.Scope, "", assignment.Action, assignment.Scope.ResourceID, DataScope{Type: "explicit_set", IDs: []string{assignment.TaskID}}, assignment.Validity)
			if err != nil && !slices.Contains(automatic, id) {
				return err
			}
		}
		if !found {
			return ErrIdentityConflict
		}
	}
	return nil
}
