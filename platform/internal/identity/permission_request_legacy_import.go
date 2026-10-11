package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// LegacyPermissionRequestSource preserves provenance without changing the old
// request, granting permissions, or reconstructing an administrator by name.
type LegacyPermissionRequestSource struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

// ImportLegacyPermissionRequest is an explicit migration operation. The caller
// must already have current v2 approval authority in the source scope. Source
// records and prior decisions remain intact; only pending requests are imported.
// Approval later uses the normal preview/CAS/authorization transaction.
func (s *SQLStore) ImportLegacyPermissionRequest(ctx context.Context, actor sharedkernel.Scope, id string, expectedRevision uint64, reason string) (PermissionRequest, error) {
	return s.importLegacyPermissionRequest(ctx, actor, id, expectedRevision, "", reason)
}

// ImportLegacyPermissionRequestFromPlan compares the complete source digest
// under the same source-row/authorization lock as the insert and audit.
func (s *SQLStore) ImportLegacyPermissionRequestFromPlan(ctx context.Context, actor sharedkernel.Scope, entry LegacyRequestMigrationEntry, reason string) (PermissionRequest, error) {
	if entry.Disposition != "ready" || !validPermissionDigest(entry.Source.Digest) {
		return PermissionRequest{}, ErrInvalidResource
	}
	return s.importLegacyPermissionRequest(ctx, actor, entry.Source.ID, entry.Source.Revision, entry.Source.Digest, reason)
}

func (s *SQLStore) importLegacyPermissionRequest(ctx context.Context, actor sharedkernel.Scope, id string, expectedRevision uint64, expectedDigest, reason string) (PermissionRequest, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil {
		return PermissionRequest{}, ErrPermissionRecorderUnavailable
	}
	if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || expectedRevision == 0 || strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return PermissionRequest{}, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PermissionRequest{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionRequest{}, err
	}
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return PermissionRequest{}, err
	}
	source, err := scanAgentAccessRequest(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at FROM platform_identity_agent_access_request WHERE id=? FOR UPDATE`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return PermissionRequest{}, ErrAccessRequestNotFound
	}
	if err != nil {
		return PermissionRequest{}, err
	}
	request := PermissionRequest{ID: source.ID, SubjectID: source.SubjectID, Scope: ManagementScope{Type: "application", TenantID: source.TenantID, DepartmentID: source.DepartmentID, ApplicationID: source.ApplicationID}, Reason: source.Reason, Status: "pending", Revision: source.Revision, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt}
	if expectedDigest != "" && (source.TenantID != actor.TenantID || source.DepartmentID != actor.DepartmentID || source.ApplicationID != actor.ApplicationID) {
		return PermissionRequest{}, ErrPermissionDenied
	}
	if err := authorizePermissionRequestDecision(owner, actor, request, s.clock().UTC()); err != nil {
		return PermissionRequest{}, err
	}
	if source.SubjectType != PrincipalUser || source.Status != AgentAccessRequestPending || source.Revision != expectedRevision || request.Scope.Validate() != nil || source.AgentInstanceID == "" {
		return PermissionRequest{}, ErrIdentityConflict
	}
	target, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, source.SubjectID)
	if err != nil {
		return PermissionRequest{}, err
	}
	// Disabled subjects and unavailable installations are preserved, not enabled.
	// The later approval validates current membership and Catalog state afresh.
	if target.Mode != "v2" || target.Principal.TenantID != source.TenantID {
		return PermissionRequest{}, ErrPermissionDenied
	}
	actions, ok := normalizeAgentAccessActions(source.Actions)
	if !ok {
		return PermissionRequest{}, ErrInvalidAccessRequest
	}
	rawSource, err := json.Marshal(source)
	if err != nil {
		return PermissionRequest{}, err
	}
	request.LegacySource = &LegacyPermissionRequestSource{ID: source.ID, Revision: source.Revision, Digest: permissionHash(rawSource)}
	if expectedDigest != "" && request.LegacySource.Digest != expectedDigest {
		return PermissionRequest{}, ErrIdentityConflict
	}
	for _, action := range actions {
		request.Items = append(request.Items, PermissionRequestItem{ID: action, Kind: "resource", Scope: request.Scope, ResourceID: source.AgentInstanceID, Action: action, DataScope: DataScope{Type: "owner"}, Outcome: "pending"})
	}
	prior, err := permissionRequestFromRow(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=?`), id))
	if err == nil {
		if prior.LegacySource == nil || *prior.LegacySource != *request.LegacySource {
			return PermissionRequest{}, ErrIdentityConflict
		}
		// Return the current request rather than a stale pending import receipt.
		return prior, tx.Commit()
	}
	if !errors.Is(err, ErrAccessRequestNotFound) {
		return PermissionRequest{}, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return PermissionRequest{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_permission_request(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?,?,?)`), request.ID, request.SubjectID, request.Scope.TenantID, request.Scope.DepartmentID, request.Scope.ApplicationID, request.Revision, string(raw), request.CreatedAt, request.UpdatedAt); err != nil {
		return PermissionRequest{}, err
	}
	now := s.clock().UTC()
	event := AdministrativeEvent{ID: "request-import-" + permissionHash([]byte(source.ID)), ActorID: actor.PrincipalID, SubjectID: request.SubjectID, Action: "permission_request.migrated", Reason: reason, Revision: request.Revision, OccurredAt: now, DetailsDigest: permissionHash(raw)}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return PermissionRequest{}, err
	}
	return request, tx.Commit()
}
