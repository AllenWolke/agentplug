package modelgovernance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const deploymentColumns = `id,tenant_id,department_id,application_id,model_version_id,environment,endpoint_ref,runtime_kind,resource_profile_json,min_replicas,max_replicas,capacity_json,health_status,status,observed_revision,revision,created_at,updated_at`

func scanDeployment(scanner interface{ Scan(...any) error }) (Deployment, error) {
	var row Deployment
	var resource, capacity []byte
	err := scanner.Scan(&row.ID, &row.TenantID, &row.DepartmentID, &row.ApplicationID, &row.ModelVersionID, &row.Environment, &row.EndpointRef, &row.RuntimeKind, &resource, &row.MinReplicas, &row.MaxReplicas, &capacity, &row.HealthStatus, &row.Status, &row.ObservedRevision, &row.Revision, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return Deployment{}, mapNotFound(err)
	}
	row.ResourceProfile = append(json.RawMessage(nil), resource...)
	row.Capacity = append(json.RawMessage(nil), capacity...)
	return row, nil
}

func (s *SQLStore) CreateDeployment(ctx context.Context, row *Deployment) error {
	if row == nil || row.ID == "" || !completeScope(Scope{TenantID: row.TenantID, DepartmentID: row.DepartmentID, ApplicationID: row.ApplicationID}) || row.ModelVersionID == "" {
		return ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var versionStatus, providerStatus string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT mv.status,p.status FROM platform_model_version mv JOIN platform_model_definition md ON md.id=mv.definition_id JOIN platform_model_provider p ON p.id=md.provider_id WHERE mv.id=? FOR UPDATE`), row.ModelVersionID).Scan(&versionStatus, &providerStatus)
	if err != nil {
		return mapNotFound(err)
	}
	if versionStatus != StatusApproved || providerStatus != StatusApproved {
		return ErrRevisionConflict
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_deployment (`+deploymentColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.TenantID, row.DepartmentID, row.ApplicationID, row.ModelVersionID, row.Environment, row.EndpointRef, row.RuntimeKind, string(row.ResourceProfile), row.MinReplicas, row.MaxReplicas, string(row.Capacity), row.HealthStatus, row.Status, row.ObservedRevision, row.Revision, now, now)
	if err != nil {
		return mapDuplicate(err)
	}
	capacityUnits, err := modelcapacity.ParseCapacityUnits(row.Capacity)
	if err != nil {
		return err
	}
	if err = modelcapacity.RegisterPoolTx(tx, modelcapacity.Deployment{ID: row.ID, TenantID: row.TenantID, DepartmentID: row.DepartmentID, ApplicationID: row.ApplicationID, ModelVersionID: row.ModelVersionID, CapacityUnits: capacityUnits}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) GetDeployment(ctx context.Context, scope Scope, id string) (Deployment, error) {
	if !completeScope(scope) {
		return Deployment{}, ErrInvalidRequest
	}
	return scanDeployment(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+deploymentColumns+` FROM platform_model_deployment WHERE tenant_id=? AND department_id=? AND application_id=? AND id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, id))
}

// GetRuntimeDeployment exposes metadata through a Port, with mandatory scope.
// 以强制作用域 Port 提供部署元数据，禁止消费者跨表 JOIN。
func (s *SQLStore) GetRuntimeDeployment(ctx context.Context, scope sharedkernel.Scope, id string) (modelcapacity.RuntimeDeployment, error) {
	row, err := s.GetDeployment(ctx, Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}, id)
	if err != nil {
		return modelcapacity.RuntimeDeployment{}, err
	}
	units, err := modelcapacity.ParseCapacityUnits(row.Capacity)
	if err != nil {
		return modelcapacity.RuntimeDeployment{}, err
	}
	return modelcapacity.RuntimeDeployment{ID: row.ID, ModelVersionID: row.ModelVersionID, EndpointRef: row.EndpointRef, CapacityUnits: units, HealthStatus: row.HealthStatus, Status: row.Status}, nil
}

func (s *SQLStore) ListDeployments(ctx context.Context, scope Scope, versionID string, limit int) ([]Deployment, error) {
	if !completeScope(scope) {
		return nil, ErrInvalidRequest
	}
	query := `SELECT ` + deploymentColumns + ` FROM platform_model_deployment WHERE tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	if versionID = strings.TrimSpace(versionID); versionID != "" {
		query += ` AND model_version_id=?`
		args = append(args, versionID)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ?`
	args = append(args, clampLimit(limit))
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Deployment, 0)
	for rows.Next() {
		row, scanErr := scanDeployment(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) UpdateDeploymentHealth(ctx context.Context, scope Scope, id string, revision uint64, health, status string) error {
	if !completeScope(scope) || !validHealthTransition(health, status) {
		return ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The trusted observer probed precisely the CAS-selected deployment
	// revision. Preserve that evidence separately from the new row revision;
	// merely creating desired state must never mark it observed.
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_deployment SET health_status=?,status=?,observed_revision=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=? AND department_id=? AND application_id=? AND id=? AND revision=? AND status<>?`), health, status, revision, scope.TenantID, scope.DepartmentID, scope.ApplicationID, id, revision, DeploymentDisabled)
	if err != nil {
		return err
	}
	if err = affectedOne(result); err != nil {
		return err
	}
	if err = modelcapacity.UpdatePoolStateTx(tx, sharedkernel.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}, id, health, status, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

const accessPolicyColumns = `id,tenant_id,department_id,application_id,installation_id,agent_version_id,principal_id,allow_local,allow_private,allow_external,allowed_providers_json,allowed_models_json,effective_from,effective_until,status,revision,created_at,updated_at`

func scanAccessPolicy(scanner interface{ Scan(...any) error }) (AccessPolicy, error) {
	var row AccessPolicy
	var providers, models []byte
	err := scanner.Scan(&row.ID, &row.TenantID, &row.DepartmentID, &row.ApplicationID, &row.InstallationID, &row.AgentVersionID, &row.PrincipalID, &row.AllowLocal, &row.AllowPrivate, &row.AllowExternal, &providers, &models, &row.EffectiveFrom, &row.EffectiveUntil, &row.Status, &row.Revision, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return AccessPolicy{}, mapNotFound(err)
	}
	if err = json.Unmarshal(providers, &row.AllowedProviders); err != nil {
		return AccessPolicy{}, fmt.Errorf("corrupt allowed provider policy JSON: %w", err)
	}
	if err = json.Unmarshal(models, &row.AllowedModels); err != nil {
		return AccessPolicy{}, fmt.Errorf("corrupt allowed model policy JSON: %w", err)
	}
	return row, nil
}

func (s *SQLStore) CreateAccessPolicy(ctx context.Context, row *AccessPolicy) error {
	if row == nil || row.ID == "" || !validPolicyScope(*row) {
		return ErrInvalidRequest
	}
	providers, err := json.Marshal(normalizeIDs(row.AllowedProviders))
	if err != nil {
		return err
	}
	models, err := json.Marshal(normalizeIDs(row.AllowedModels))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_access_policy (`+accessPolicyColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.TenantID, row.DepartmentID, row.ApplicationID, row.InstallationID, row.AgentVersionID, row.PrincipalID, row.AllowLocal, row.AllowPrivate, row.AllowExternal, string(providers), string(models), row.EffectiveFrom, row.EffectiveUntil, row.Status, row.Revision, now, now)
	return mapDuplicate(err)
}

func (s *SQLStore) GetAccessPolicy(ctx context.Context, scope Scope, id string) (AccessPolicy, error) {
	if !completeScope(scope) {
		return AccessPolicy{}, ErrInvalidRequest
	}
	return scanAccessPolicy(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+accessPolicyColumns+` FROM platform_model_access_policy WHERE tenant_id=? AND id=? AND (department_id='' OR department_id=?) AND (application_id='' OR application_id=?)`), scope.TenantID, id, scope.DepartmentID, scope.ApplicationID))
}

func (s *SQLStore) ListAccessPolicies(ctx context.Context, scope Scope, limit int) ([]AccessPolicy, error) {
	if !completeScope(scope) {
		return nil, ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+accessPolicyColumns+` FROM platform_model_access_policy WHERE tenant_id=? AND (department_id='' OR department_id=?) AND (application_id='' OR application_id=?) ORDER BY created_at DESC,id DESC LIMIT ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AccessPolicy, 0)
	for rows.Next() {
		row, scanErr := scanAccessPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) UpdateAccessPolicyStatus(ctx context.Context, scope Scope, id string, revision uint64, status string) error {
	if !completeScope(scope) {
		return ErrInvalidRequest
	}
	expected := PolicyDraft
	switch status {
	case PolicyApproved:
		expected = PolicyDraft
	case PolicyRevoked:
		expected = PolicyApproved
	default:
		return ErrInvalidRequest
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_access_policy SET status=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=? AND id=? AND (department_id='' OR department_id=?) AND (application_id='' OR application_id=?) AND revision=? AND status=?`), status, scope.TenantID, id, scope.DepartmentID, scope.ApplicationID, revision, expected)
	if err != nil {
		return err
	}
	return affectedOne(result)
}

func (s *SQLStore) ListApplicableAccessPolicies(ctx context.Context, scope ModelAccessScope) ([]AccessPolicy, error) {
	if !validAccessScope(scope) {
		return nil, ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+accessPolicyColumns+` FROM platform_model_access_policy WHERE tenant_id=? AND status=? AND (department_id='' OR department_id=?) AND (application_id='' OR application_id=?) AND (installation_id='' OR installation_id=?) AND (agent_version_id='' OR agent_version_id=?) AND (principal_id='' OR principal_id=?) AND (effective_from IS NULL OR effective_from<=CURRENT_TIMESTAMP) AND (effective_until IS NULL OR effective_until>=CURRENT_TIMESTAMP) ORDER BY id`), scope.TenantID, PolicyApproved, scope.DepartmentID, scope.ApplicationID, scope.InstallationID, scope.AgentVersionID, scope.PrincipalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AccessPolicy, 0)
	for rows.Next() {
		row, scanErr := scanAccessPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) GetResolvedVersion(ctx context.Context, versionID string) (ResolvedModel, error) {
	var model ResolvedModel
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT mv.id,mv.definition_id,md.provider_id,p.provider_key,md.model_key,md.kind,p.trust_zone,mv.status,p.status FROM platform_model_version mv JOIN platform_model_definition md ON md.id=mv.definition_id JOIN platform_model_provider p ON p.id=md.provider_id WHERE mv.id=?`), versionID).Scan(&model.VersionID, &model.DefinitionID, &model.ProviderID, &model.ProviderKey, &model.ModelKey, &model.Kind, &model.TrustZone, &model.VersionStatus, &model.ProviderStatus)
	return model, mapNotFound(err)
}

var _ Store = (*SQLStore)(nil)

func completeScope(scope Scope) bool {
	return validScopeValue(scope.TenantID) && validScopeValue(scope.DepartmentID) && validScopeValue(scope.ApplicationID)
}

func validScopeValue(value string) bool {
	return validGovernanceID(value, 64)
}

func validPolicyScope(scope AccessPolicy) bool {
	if !validScopeValue(scope.TenantID) || !validScopeValue(scope.DepartmentID) && scope.DepartmentID != "" ||
		!validScopeValue(scope.ApplicationID) && scope.ApplicationID != "" || !validScopeValue(scope.InstallationID) && scope.InstallationID != "" ||
		!validScopeValue(scope.AgentVersionID) && scope.AgentVersionID != "" || !validGovernanceID(scope.PrincipalID, 128) && scope.PrincipalID != "" {
		return false
	}
	if scope.ApplicationID != "" && scope.DepartmentID == "" || scope.InstallationID != "" && scope.ApplicationID == "" || scope.AgentVersionID != "" && scope.InstallationID == "" {
		return false
	}
	return true
}

func normalizeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validGovernanceID(value, 128) {
			continue
		}
		if _, found := seen[value]; !found {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func validAccessScope(scope ModelAccessScope) bool {
	return validScopeValue(scope.TenantID) && validScopeValue(scope.DepartmentID) && validScopeValue(scope.ApplicationID) && validScopeValue(scope.InstallationID) && validScopeValue(scope.AgentVersionID) && validGovernanceID(scope.PrincipalID, 128)
}

func validGovernanceID(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen || strings.TrimSpace(value) != value {
		return false
	}
	for i, r := range value {
		if r > 127 || !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || (i > 0 && strings.ContainsRune("._:-", r))) {
			return false
		}
	}
	return true
}

func validHealthTransition(health, status string) bool {
	switch health {
	case "unknown", "warming", "ready", "degraded", "unavailable", "draining":
	default:
		return false
	}
	expected, valid := DeploymentStatusForHealth(health)
	return valid && expected == status
}
