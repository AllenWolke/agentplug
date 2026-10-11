package modelgovernance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Store is the model governance persistence port. Global catalog operations
// and tenant-scoped deployment/policy operations have distinct methods.
type Store interface {
	EnsureSchema(context.Context) error
	CreateProvider(context.Context, *Provider) error
	GetProvider(context.Context, string) (Provider, error)
	ListProviders(context.Context, int) ([]Provider, error)
	UpdateProviderStatus(context.Context, string, uint64, string) error
	CreateDefinition(context.Context, *ModelDefinition) error
	GetDefinition(context.Context, string) (ModelDefinition, error)
	ListDefinitions(context.Context, string, int) ([]ModelDefinition, error)
	CreateVersion(context.Context, *ModelVersion) error
	GetVersion(context.Context, string, string) (ModelVersion, error)
	ListVersions(context.Context, string, int) ([]ModelVersion, error)
	ApproveVersion(context.Context, string, uint64) error
	CreatePriceVersion(context.Context, *PriceVersion) error
	GetPriceVersion(context.Context, string) (PriceVersion, error)
	ListPriceVersions(context.Context, string, int) ([]PriceVersion, error)
	ApprovePriceVersion(context.Context, string, uint64) error
	ResolvePrice(context.Context, string, time.Time) (PriceVersion, error)
	CreateDeployment(context.Context, *Deployment) error
	GetDeployment(context.Context, Scope, string) (Deployment, error)
	ListDeployments(context.Context, Scope, string, int) ([]Deployment, error)
	UpdateDeploymentHealth(context.Context, Scope, string, uint64, string, string) error
	CreateAccessPolicy(context.Context, *AccessPolicy) error
	GetAccessPolicy(context.Context, Scope, string) (AccessPolicy, error)
	ListAccessPolicies(context.Context, Scope, int) ([]AccessPolicy, error)
	UpdateAccessPolicyStatus(context.Context, Scope, string, uint64, string) error
	ListApplicableAccessPolicies(context.Context, ModelAccessScope) ([]AccessPolicy, error)
	GetResolvedVersion(context.Context, string) (ResolvedModel, error)
}

// SQLStore owns the PostgreSQL tables for catalog metadata and scoped governance.
type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("model governance database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_model_provider (
			id VARCHAR(36) PRIMARY KEY,
			provider_key VARCHAR(128) NOT NULL,
			display_name VARCHAR(128) NOT NULL,
			type VARCHAR(32) NOT NULL,
			trust_zone VARCHAR(24) NOT NULL,
			endpoint_ref VARCHAR(255) NOT NULL,
			network_zone VARCHAR(64) NOT NULL DEFAULT '',
			region VARCHAR(64) NOT NULL DEFAULT '',
			owner_id VARCHAR(128) NOT NULL,
			secret_ref VARCHAR(255) NOT NULL,
			retention_mode VARCHAR(32) NOT NULL,
			training_usage VARCHAR(32) NOT NULL,
			compliance_status VARCHAR(32) NOT NULL,
			capabilities_json JSON NOT NULL,
			status VARCHAR(24) NOT NULL,
			health_status VARCHAR(24) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_model_provider_key UNIQUE (provider_key));
CREATE INDEX IF NOT EXISTS idx_platform_model_provider_status ON platform_model_provider (status, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_model_definition (
			id VARCHAR(36) PRIMARY KEY,
			provider_id VARCHAR(36) NOT NULL,
			model_key VARCHAR(128) NOT NULL,
			kind VARCHAR(24) NOT NULL,
			display_name VARCHAR(128) NOT NULL,
			capabilities_json JSON NOT NULL,
			context_limit INT NOT NULL,
			lifecycle_status VARCHAR(24) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_model_definition_key UNIQUE (provider_id, model_key));
CREATE INDEX IF NOT EXISTS idx_platform_model_definition_provider ON platform_model_definition (provider_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_model_version (
			id VARCHAR(36) PRIMARY KEY,
			definition_id VARCHAR(36) NOT NULL,
			semantic_version VARCHAR(64) NOT NULL,
			provider_fingerprint VARCHAR(255) NOT NULL,
			artifact_digest VARCHAR(128) NOT NULL DEFAULT '',
			quantization VARCHAR(64) NOT NULL DEFAULT '',
			capability_hash VARCHAR(80) NOT NULL DEFAULT '',
			status VARCHAR(24) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_model_version_semver UNIQUE (definition_id, semantic_version));
CREATE INDEX IF NOT EXISTS idx_platform_model_version_definition ON platform_model_version (definition_id, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_model_price_version (
			id VARCHAR(36) PRIMARY KEY,
			model_version_id VARCHAR(36) NOT NULL,
			currency VARCHAR(3) NOT NULL,
			input_micros_per_1k_tokens BIGINT NOT NULL,
			output_micros_per_1k_tokens BIGINT NOT NULL,
			effective_from TIMESTAMPTZ(6) NOT NULL,
			effective_until TIMESTAMPTZ(6) NULL,
			content_hash VARCHAR(71) NOT NULL,
			status VARCHAR(24) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_model_price_hash UNIQUE (model_version_id,content_hash));
CREATE INDEX IF NOT EXISTS idx_platform_model_price_effective ON platform_model_price_version (model_version_id,status,effective_from,effective_until);`,
		`CREATE TABLE IF NOT EXISTS platform_model_deployment (
			id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			department_id VARCHAR(64) NOT NULL,
			application_id VARCHAR(64) NOT NULL,
			model_version_id VARCHAR(36) NOT NULL,
			environment VARCHAR(32) NOT NULL,
			endpoint_ref VARCHAR(255) NOT NULL,
			runtime_kind VARCHAR(32) NOT NULL,
			resource_profile_json JSON NOT NULL,
			min_replicas INT NOT NULL,
			max_replicas INT NOT NULL,
			capacity_json JSON NOT NULL,
			health_status VARCHAR(24) NOT NULL,
			status VARCHAR(24) NOT NULL,
			observed_revision NUMERIC(20,0) CHECK (observed_revision>=0 AND observed_revision<=18446744073709551615) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_model_deployment_scope ON platform_model_deployment (tenant_id,department_id,application_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_deployment_version ON platform_model_deployment (model_version_id,created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_model_access_policy (
			id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			department_id VARCHAR(64) NOT NULL DEFAULT '',
			application_id VARCHAR(64) NOT NULL DEFAULT '',
			installation_id VARCHAR(64) NOT NULL DEFAULT '',
			agent_version_id VARCHAR(64) NOT NULL DEFAULT '',
			principal_id VARCHAR(128) NOT NULL DEFAULT '',
			allow_local BOOLEAN NOT NULL,
			allow_private BOOLEAN NOT NULL,
			allow_external BOOLEAN NOT NULL,
			allowed_providers_json JSON NOT NULL,
			allowed_models_json JSON NOT NULL,
			effective_from TIMESTAMPTZ(6) NULL,
			effective_until TIMESTAMPTZ(6) NULL,
			status VARCHAR(24) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_model_access_policy_scope ON platform_model_access_policy (tenant_id,department_id,application_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_model_access_policy_installation ON platform_model_access_policy (installation_id,agent_version_id,principal_id);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("model governance schema: %w", err)
		}
	}
	// Capacity schema is owned by its migration module, never this repository.
	// 容量表由容量模块迁移负责，治理Repository不得构造其他模块SQL实现。
	return nil
}

func (s *SQLStore) CreateProvider(ctx context.Context, row *Provider) error {
	if row == nil || !(Scope{TenantID: row.TenantID, DepartmentID: row.DepartmentID, ApplicationID: row.ApplicationID}).IsGlobal() {
		return ErrInvalidRequest
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_provider
		(id,provider_key,display_name,type,trust_zone,endpoint_ref,network_zone,region,owner_id,secret_ref,retention_mode,training_usage,compliance_status,capabilities_json,status,health_status,revision,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.ProviderKey, row.DisplayName, row.Type, row.TrustZone, row.EndpointRef, row.NetworkZone, row.Region, row.OwnerID, row.SecretRef, row.RetentionMode, row.TrainingUsage, row.ComplianceStatus, string(row.Capabilities), row.Status, row.HealthStatus, row.Revision, row.CreatedAt, row.UpdatedAt)
	return mapDuplicate(err)
}

const providerColumns = `id,provider_key,display_name,type,trust_zone,endpoint_ref,network_zone,region,owner_id,secret_ref,retention_mode,training_usage,compliance_status,capabilities_json,status,health_status,revision,created_at,updated_at`

func scanProvider(scanner interface{ Scan(...any) error }) (Provider, error) {
	var row Provider
	var capabilities []byte
	err := scanner.Scan(&row.ID, &row.ProviderKey, &row.DisplayName, &row.Type, &row.TrustZone, &row.EndpointRef, &row.NetworkZone, &row.Region, &row.OwnerID, &row.SecretRef, &row.RetentionMode, &row.TrainingUsage, &row.ComplianceStatus, &capabilities, &row.Status, &row.HealthStatus, &row.Revision, &row.CreatedAt, &row.UpdatedAt)
	row.Capabilities = append(row.Capabilities[:0], capabilities...)
	return row, mapNotFound(err)
}

func (s *SQLStore) GetProvider(ctx context.Context, id string) (Provider, error) {
	return scanProvider(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+providerColumns+` FROM platform_model_provider WHERE id=?`), id))
}

func (s *SQLStore) ListProviders(ctx context.Context, limit int) ([]Provider, error) {
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+providerColumns+` FROM platform_model_provider ORDER BY created_at DESC,id DESC LIMIT ?`), clampLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Provider, 0)
	for rows.Next() {
		row, scanErr := scanProvider(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) UpdateProviderStatus(ctx context.Context, id string, revision uint64, status string) error {
	expected := ""
	switch status {
	case StatusApproved:
		expected = StatusDraft
	case StatusDisabled:
		expected = StatusApproved
	default:
		return ErrInvalidRequest
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_provider SET status=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND revision=? AND status=?`), status, id, revision, expected)
	if err != nil {
		return err
	}
	return affectedOne(result)
}

func (s *SQLStore) CreateDefinition(ctx context.Context, row *ModelDefinition) error {
	if row == nil || !(Scope{TenantID: row.TenantID, DepartmentID: row.DepartmentID, ApplicationID: row.ApplicationID}).IsGlobal() {
		return ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var providerStatus string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_provider WHERE id=? FOR UPDATE`), row.ProviderID).Scan(&providerStatus); err != nil {
		return mapNotFound(err)
	}
	if providerStatus != StatusApproved {
		return ErrRevisionConflict
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_definition (id,provider_id,model_key,kind,display_name,capabilities_json,context_limit,lifecycle_status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.ProviderID, row.ModelKey, row.Kind, row.DisplayName, string(row.Capabilities), row.ContextLimit, row.LifecycleStatus, row.Revision, now, now); err != nil {
		return mapDuplicate(err)
	}
	return tx.Commit()
}

const definitionColumns = `id,provider_id,model_key,kind,display_name,capabilities_json,context_limit,lifecycle_status,revision,created_at,updated_at`

func scanDefinition(scanner interface{ Scan(...any) error }) (ModelDefinition, error) {
	var row ModelDefinition
	var capabilities []byte
	err := scanner.Scan(&row.ID, &row.ProviderID, &row.ModelKey, &row.Kind, &row.DisplayName, &capabilities, &row.ContextLimit, &row.LifecycleStatus, &row.Revision, &row.CreatedAt, &row.UpdatedAt)
	row.Capabilities = append(row.Capabilities[:0], capabilities...)
	return row, mapNotFound(err)
}

func (s *SQLStore) GetDefinition(ctx context.Context, id string) (ModelDefinition, error) {
	return scanDefinition(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+definitionColumns+` FROM platform_model_definition WHERE id=?`), id))
}

func (s *SQLStore) ListDefinitions(ctx context.Context, providerID string, limit int) ([]ModelDefinition, error) {
	query := `SELECT ` + definitionColumns + ` FROM platform_model_definition`
	args := []any{}
	if providerID != "" {
		query += ` WHERE provider_id=?`
		args = append(args, providerID)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ?`
	args = append(args, clampLimit(limit))
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ModelDefinition, 0)
	for rows.Next() {
		row, scanErr := scanDefinition(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) CreateVersion(ctx context.Context, row *ModelVersion) error {
	if row == nil {
		return ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var definitionStatus, providerStatus string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT md.lifecycle_status,p.status FROM platform_model_definition md JOIN platform_model_provider p ON p.id=md.provider_id WHERE md.id=? FOR UPDATE`), row.DefinitionID).Scan(&definitionStatus, &providerStatus)
	if err != nil {
		return mapNotFound(err)
	}
	if definitionStatus != StatusDraft || providerStatus != StatusApproved {
		return ErrRevisionConflict
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_version (id,definition_id,semantic_version,provider_fingerprint,artifact_digest,quantization,capability_hash,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.DefinitionID, row.SemanticVersion, row.ProviderFingerprint, row.ArtifactDigest, row.Quantization, row.CapabilityHash, row.Status, row.Revision, now, now); err != nil {
		return mapDuplicate(err)
	}
	return tx.Commit()
}

const versionColumns = `id,definition_id,semantic_version,provider_fingerprint,artifact_digest,quantization,capability_hash,status,revision,created_at,updated_at`

func scanVersion(scanner interface{ Scan(...any) error }) (ModelVersion, error) {
	var row ModelVersion
	err := scanner.Scan(&row.ID, &row.DefinitionID, &row.SemanticVersion, &row.ProviderFingerprint, &row.ArtifactDigest, &row.Quantization, &row.CapabilityHash, &row.Status, &row.Revision, &row.CreatedAt, &row.UpdatedAt)
	return row, mapNotFound(err)
}

func (s *SQLStore) GetVersion(ctx context.Context, definitionID, id string) (ModelVersion, error) {
	return scanVersion(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+versionColumns+` FROM platform_model_version WHERE definition_id=? AND id=?`), definitionID, id))
}

func (s *SQLStore) ListVersions(ctx context.Context, definitionID string, limit int) ([]ModelVersion, error) {
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+versionColumns+` FROM platform_model_version WHERE definition_id=? ORDER BY created_at DESC,id DESC LIMIT ?`), definitionID, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ModelVersion, 0)
	for rows.Next() {
		row, scanErr := scanVersion(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) ApproveVersion(ctx context.Context, id string, revision uint64) error {
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_version SET status=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND revision=? AND status=?`), StatusApproved, id, revision, StatusDraft)
	if err != nil {
		return err
	}
	return affectedOne(result)
}

func (s *SQLStore) CreatePriceVersion(ctx context.Context, row *PriceVersion) error {
	if err := validatePriceVersion(row); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var versionStatus, providerStatus, trustZone, modelKind string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT mv.status,p.status,p.trust_zone,md.kind FROM platform_model_version mv JOIN platform_model_definition md ON md.id=mv.definition_id JOIN platform_model_provider p ON p.id=md.provider_id WHERE mv.id=? FOR UPDATE`), row.ModelVersionID).Scan(&versionStatus, &providerStatus, &trustZone, &modelKind)
	if err != nil {
		return mapNotFound(err)
	}
	if versionStatus != StatusApproved || providerStatus != StatusApproved {
		return ErrRevisionConflict
	}
	if err = validatePriceRates(trustZone, modelKind, row.InputMicrosPer1K, row.OutputMicrosPer1K); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT `+priceColumns+` FROM platform_model_price_version WHERE model_version_id=? FOR UPDATE`), row.ModelVersionID)
	if err != nil {
		return err
	}
	for rows.Next() {
		existing, scanErr := scanPriceVersion(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		if priceIntervalsOverlap(*row, existing) {
			rows.Close()
			return ErrPriceOverlap
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_price_version (id,model_version_id,currency,input_micros_per_1k_tokens,output_micros_per_1k_tokens,effective_from,effective_until,content_hash,status,revision,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.ModelVersionID, row.Currency, row.InputMicrosPer1K, row.OutputMicrosPer1K, row.EffectiveFrom, row.EffectiveUntil, row.ContentHash, row.Status, row.Revision, row.CreatedBy, now, now)
	if err != nil {
		return mapDuplicate(err)
	}
	return tx.Commit()
}

func (s *SQLStore) GetPriceVersion(ctx context.Context, id string) (PriceVersion, error) {
	return scanPriceVersion(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+priceColumns+` FROM platform_model_price_version WHERE id=?`), id))
}

func (s *SQLStore) ListPriceVersions(ctx context.Context, modelVersionID string, limit int) ([]PriceVersion, error) {
	query := `SELECT ` + priceColumns + ` FROM platform_model_price_version`
	args := []any{}
	if modelVersionID != "" {
		query += ` WHERE model_version_id=?`
		args = append(args, modelVersionID)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ?`
	args = append(args, clampLimit(limit))
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]PriceVersion, 0)
	for rows.Next() {
		row, scanErr := scanPriceVersion(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLStore) ApprovePriceVersion(ctx context.Context, id string, revision uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var modelVersionID string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT model_version_id FROM platform_model_price_version WHERE id=?`), id).Scan(&modelVersionID); err != nil {
		return mapNotFound(err)
	}
	var versionStatus string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_version WHERE id=? FOR UPDATE`), modelVersionID).Scan(&versionStatus); err != nil {
		return mapNotFound(err)
	}
	current, err := scanPriceVersion(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+priceColumns+` FROM platform_model_price_version WHERE id=? FOR UPDATE`), id))
	if err != nil {
		return err
	}
	// Lock the parent model-version row before the price rows so all concurrent
	// creates and approvals for this version use a consistent lock order.
	if versionStatus != StatusApproved || current.Revision != revision || current.Status != StatusDraft {
		return ErrRevisionConflict
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT effective_from,effective_until FROM platform_model_price_version WHERE model_version_id=? AND status=? AND id<>? FOR UPDATE`), modelVersionID, StatusApproved, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var existing PriceVersion
		var until sql.NullTime
		if err = rows.Scan(&existing.EffectiveFrom, &until); err != nil {
			rows.Close()
			return err
		}
		// The query is already restricted to this model version, but the shared
		// interval predicate also compares IDs. Preserve that identity here so
		// approval remains a second line of defense against overlapping prices.
		// 查询已限定模型版本；共享区间判定仍需显式填入版本 ID，避免审批绕过重叠检查。
		existing.ModelVersionID = modelVersionID
		if until.Valid {
			existing.EffectiveUntil = &until.Time
		}
		if priceIntervalsOverlap(current, existing) {
			rows.Close()
			return ErrPriceOverlap
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_price_version SET status=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND revision=? AND status=?`), StatusApproved, id, revision, StatusDraft)
	if err != nil {
		return err
	}
	if err = affectedOne(result); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolvePrice returns the unique approved price effective at at. A second
// matching row is treated as corrupted catalog state, never as arbitrary pick.
func (s *SQLStore) ResolvePrice(ctx context.Context, modelVersionID string, at time.Time) (PriceVersion, error) {
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+priceColumns+` FROM platform_model_price_version WHERE model_version_id=? AND status=? AND effective_from<=? AND (effective_until IS NULL OR effective_until>?) ORDER BY effective_from DESC,id DESC LIMIT 2`), modelVersionID, StatusApproved, at.UTC(), at.UTC())
	if err != nil {
		return PriceVersion{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return PriceVersion{}, err
		}
		return PriceVersion{}, ErrNotFound
	}
	row, err := scanPriceVersion(rows)
	if err != nil {
		return PriceVersion{}, err
	}
	if rows.Next() {
		return PriceVersion{}, ErrPriceOverlap
	}
	if err = rows.Err(); err != nil {
		return PriceVersion{}, err
	}
	return row, nil
}

func clampLimit(value int) int {
	if value < 1 {
		return 50
	}
	if value > 200 {
		return 200
	}
	return value
}

func affectedOne(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func mapDuplicate(err error) error {
	if err == nil {
		return nil
	}
	if sqlutil.IsUniqueViolation(err) {
		return fmt.Errorf("%w: %v", ErrAlreadyExists, err)
	}
	return err
}

var _ Store = (*SQLStore)(nil)
var _ PriceResolver = (*SQLStore)(nil)
