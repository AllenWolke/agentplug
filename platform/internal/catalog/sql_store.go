package catalog

// SQL persistence for the modular-monolith catalog boundary.
// 模块化单体 Catalog 边界的 SQL 持久化实现。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func catalogPersistenceError(operation string, err error) error {
	if sqlutil.IsUniqueViolation(err) {
		return fmt.Errorf("%s: %w", operation, ErrCatalogConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

var (
	ErrDefinitionNotFound     = errors.New("catalog definition not found")
	ErrVersionNotFound        = errors.New("catalog version not found")
	ErrInstallationNotFound   = errors.New("catalog installation not found")
	ErrDefinitionNotPublished = errors.New("catalog definition is not published")
	ErrVersionNotPublished    = errors.New("catalog version is not published")
	ErrAgentMismatch          = errors.New("catalog agent does not match installation")
	ErrCatalogConflict        = errors.New("catalog revision conflict")
	ErrScopeReference         = errors.New("catalog installation references inactive or unknown identity scope")
)

// Store is the catalog port consumed by the HTTP module. Keeping this
// interface smaller than SQLStore allows the same module to be moved behind a
// remote repository when the modular monolith is split into services.
// Store 是 HTTP 模块依赖的 Catalog 端口；保持窄接口，未来拆分微服务时可替换为远程仓储。
type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	CreateDefinition(context.Context, Definition) error
	GetDefinition(context.Context, string) (Definition, error)
	CreateVersion(context.Context, Version) error
	GetVersion(context.Context, string) (Version, error)
	TransitionVersion(context.Context, string, DefinitionStatus, DefinitionStatus, uint64) error
	CreateInstallation(context.Context, Installation) error
	GetInstallation(context.Context, string) (Installation, error)
	TransitionInstallation(context.Context, string, InstallationStatus, InstallationStatus, uint64) error
	RollbackInstallation(context.Context, string, string, uint64) error
	CreateDeployment(context.Context, Deployment) (Deployment, error)
	ListDeployments(context.Context, string, string, string, string, int) ([]Deployment, error)
	ObserveDeployment(context.Context, string, string, string, string, string, uint64, DeploymentStatus) error
}

// CatalogListReader exposes bounded control-plane projections. Installation
// queries always require the full tenant/department/application scope.
// CatalogListReader 提供有界控制面列表投影；安装列表必须指定完整作用域。
type CatalogListReader interface {
	ListDefinitions(context.Context, int) ([]Definition, error)
	ListVersions(context.Context, string, int) ([]Version, error)
	ListInstallations(context.Context, string, string, string, int) ([]Installation, error)
}

// InstallableCatalogReader exposes only globally published definitions and
// versions to an authorized application scope. It deliberately omits drafts,
// raw manifests, schemas, and runtime endpoint material.
// InstallableCatalogReader 仅向已授权应用作用域暴露已发布定义/版本，不返回草稿、原始 Manifest、Schema 或运行时地址。
type InstallableCatalogReader interface {
	ListPublishedDefinitions(context.Context, int) ([]Definition, error)
	ListPublishedVersions(context.Context, string, int) ([]PublishedVersion, error)
}

// AvailableAgent is the browser-safe projection of a published Agent installed
// in the caller's application scope. It intentionally omits endpoint refs and
// deployment secrets.
// AvailableAgent 是当前应用已发布 Agent 的浏览器安全投影，不包含 Endpoint 或部署密钥。
type AvailableAgent struct {
	AgentID         string `json:"agent_id"`
	Name            string `json:"name"`
	SemanticVersion string `json:"semantic_version"`
	VersionID       string `json:"version_id"`
	InstallationID  string `json:"installation_id"`
}

// AvailableAgentReader is an optional read port so isolated Catalog adapters
// need not implement browser projections they do not expose.
// AvailableAgentReader 是可选读端口，隔离的 Catalog Adapter 无须实现浏览器投影。
type AvailableAgentReader interface {
	ListAvailableAgents(context.Context, string, string, string) ([]AvailableAgent, error)
}

// DefinitionLifecycleStore and InstallationLifecycleStore are optional
// extensions of Store. Keeping lifecycle writes as opt-in preserves the narrow
// repository seam for remote adapters while allowing the SQL implementation to
// expose the real CAS operations.
type DefinitionLifecycleStore interface {
	TransitionDefinition(context.Context, string, DefinitionStatus, DefinitionStatus, uint64) error
}

type InstallationLifecycleStore interface {
	UninstallInstallation(context.Context, string, uint64) error
}

// SQLStore owns only the catalog tables. Other modules must use the public
// methods instead of joining these tables directly.
// SQLStore 只拥有 Catalog 表；其他模块必须调用公开方法，不能直接 JOIN。
type SQLStore struct {
	db               *sql.DB
	driver           string
	clock            func() time.Time
	releaseGuard     ReleaseGuard
	releaseAuthorize ReleaseAuthorizer
	releaseRecord    ReleaseRecorder
}

func NewSQLStore(db *sql.DB, driver string) *SQLStore {
	return &SQLStore{db: db, driver: strings.ToLower(strings.TrimSpace(driver)), clock: func() time.Time { return time.Now().UTC() }}
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("catalog database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_catalog_definition (
			id VARCHAR(128) PRIMARY KEY,
			publisher_id VARCHAR(128) NOT NULL,
			agent_key VARCHAR(128) NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			status VARCHAR(32) NOT NULL,
			revision BIGINT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_catalog_definition_agent UNIQUE (publisher_id, agent_key)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_definition_metadata (
			definition_id VARCHAR(128) PRIMARY KEY,
			description TEXT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_version (
			id VARCHAR(128) PRIMARY KEY,
			definition_id VARCHAR(128) NOT NULL,
			semantic_version VARCHAR(64) NOT NULL,
			manifest_hash VARCHAR(128) NOT NULL,
			artifact_digest VARCHAR(255) NOT NULL,
			input_schema TEXT NOT NULL,
			output_schema TEXT NOT NULL,
			status VARCHAR(32) NOT NULL,
			revision BIGINT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			evaluated_at TIMESTAMPTZ(6) NULL,
			published_at TIMESTAMPTZ(6) NULL,
			CONSTRAINT uq_catalog_version UNIQUE (definition_id, semantic_version)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_version_artifact (
			version_id VARCHAR(128) PRIMARY KEY,
			manifest_json JSON NOT NULL,
			input_schema_json JSON NOT NULL,
			output_schema_json JSON NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_installation (
			id VARCHAR(128) PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			agent_id VARCHAR(128) NOT NULL,
			version_id VARCHAR(128) NOT NULL,
			status VARCHAR(32) NOT NULL,
			revision BIGINT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_catalog_installation_scope UNIQUE (tenant_id, department_id, application_id, agent_id)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_installation_options (
			installation_id VARCHAR(128) PRIMARY KEY,
			display_name VARCHAR(255) NOT NULL,
			deployment_mode VARCHAR(32) NOT NULL,
			drain_policy VARCHAR(32) NOT NULL,
			retention_policy_id VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_catalog_deployment (
			id VARCHAR(128) PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL,
			agent_installation_id VARCHAR(128) NOT NULL,
			artifact_digest VARCHAR(255) NOT NULL,
			transport VARCHAR(16) NOT NULL,
			endpoint_ref VARCHAR(512) NOT NULL,
			placement_policy JSON NOT NULL,
			resource_policy JSON NOT NULL,
			status VARCHAR(32) NOT NULL,
			desired_revision NUMERIC(20,0) CHECK (desired_revision>=0 AND desired_revision<=18446744073709551615) NOT NULL,
			observed_revision NUMERIC(20,0) CHECK (observed_revision>=0 AND observed_revision<=18446744073709551615) NOT NULL,
			manifest_hash VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_catalog_deployment_revision UNIQUE (tenant_id,department_id,application_id,agent_installation_id,desired_revision));
CREATE INDEX IF NOT EXISTS idx_catalog_deployment_scope ON platform_catalog_deployment (tenant_id,department_id,application_id,agent_installation_id);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("catalog schema: %w", err)
		}
	}
	return s.EnsureReleaseSubmissionSchema(ctx)
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("catalog database is required")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLStore) CreateDefinition(ctx context.Context, definition Definition) error {
	return s.createDefinition(ctx, definition, nil)
}

func (s *SQLStore) createDefinition(ctx context.Context, definition Definition, actor *ControlActor) error {
	if err := definition.Validate(); err != nil {
		return err
	}
	if definition.Status != DefinitionDraft || definition.Revision != 1 {
		return ErrInvalidDefinition
	}
	now := s.clock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create catalog definition: %w", err)
	}
	defer tx.Rollback()
	if actor != nil {
		if err := s.beginRelease(ctx, tx, *actor, ControlSubmit); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_definition
		(id,publisher_id,agent_key,display_name,status,revision,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?)`), definition.ID, definition.PublisherID, definition.AgentKey,
		definition.DisplayName, definition.Status, definition.Revision, now, now)
	if err != nil {
		return catalogPersistenceError("create catalog definition", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_definition_metadata (definition_id,description,created_at) VALUES (?,?,?)`), definition.ID, definition.Description, now); err != nil {
		return fmt.Errorf("create catalog definition metadata: %w", err)
	}
	if actor != nil {
		if err := s.recordSubmission(ctx, tx, "definition", definition.ID, *actor, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit catalog definition: %w", err)
	}
	return nil
}

func (s *SQLStore) GetDefinition(ctx context.Context, id string) (Definition, error) {
	var row Definition
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT d.id,d.publisher_id,d.agent_key,d.display_name,m.description,d.status,d.revision,COALESCE(p.submitted_by,''),COALESCE(p.approved_by,'')
		FROM platform_catalog_definition d JOIN platform_catalog_definition_metadata m ON m.definition_id=d.id LEFT JOIN platform_catalog_submission p ON p.object_kind='definition' AND p.object_id=d.id WHERE d.id=?`), id).
		Scan(&row.ID, &row.PublisherID, &row.AgentKey, &row.DisplayName, &row.Description, &row.Status, &row.Revision, &row.SubmittedBy, &row.ApprovedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Definition{}, ErrDefinitionNotFound
	}
	if err != nil {
		return Definition{}, fmt.Errorf("get catalog definition: %w", err)
	}
	return row, nil
}

func (s *SQLStore) ListDefinitions(ctx context.Context, limit int) ([]Definition, error) {
	if limit <= 0 || limit > 100 {
		return nil, ErrInvalidDefinition
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT d.id,d.publisher_id,d.agent_key,d.display_name,m.description,d.status,d.revision,COALESCE(p.submitted_by,''),COALESCE(p.approved_by,'')
		FROM platform_catalog_definition d JOIN platform_catalog_definition_metadata m ON m.definition_id=d.id LEFT JOIN platform_catalog_submission p ON p.object_kind='definition' AND p.object_id=d.id
		ORDER BY d.created_at DESC,d.id ASC LIMIT ?`), limit)
	if err != nil {
		return nil, fmt.Errorf("list catalog definitions: %w", err)
	}
	defer rows.Close()
	items := make([]Definition, 0)
	for rows.Next() {
		var item Definition
		if err := rows.Scan(&item.ID, &item.PublisherID, &item.AgentKey, &item.DisplayName, &item.Description, &item.Status, &item.Revision, &item.SubmittedBy, &item.ApprovedBy); err != nil {
			return nil, fmt.Errorf("scan catalog definition: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate catalog definitions: %w", err)
	}
	return items, nil
}

// TransitionDefinition applies an optimistic-concurrency guarded definition
// lifecycle change. Keeping this separate from version transitions prevents a
// caller from treating a published version as a published catalog entry.
func (s *SQLStore) TransitionDefinition(ctx context.Context, id string, from, to DefinitionStatus, expectedRevision uint64) error {
	if strings.TrimSpace(id) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	if err := ValidateDefinitionTransition(from, to); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_definition
		SET status=?, revision=revision+1, updated_at=?
		WHERE id=? AND status=? AND revision=? AND EXISTS (SELECT 1 FROM platform_catalog_definition_metadata WHERE definition_id=?)`), to, s.clock(), id, from, expectedRevision, id)
	if err != nil {
		return fmt.Errorf("transition catalog definition: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("transition catalog definition rows: %w", err)
	}
	if rows != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func (s *SQLStore) CreateVersion(ctx context.Context, version Version) error {
	return s.createVersion(ctx, version, nil)
}

func (s *SQLStore) createVersion(ctx context.Context, version Version, actor *ControlActor) error {
	if err := version.Validate(); err != nil {
		return err
	}
	if version.Status != DefinitionDraft || version.Revision != 1 {
		return ErrInvalidVersion
	}
	var agentKey string
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT d.agent_key FROM platform_catalog_definition d JOIN platform_catalog_definition_metadata m ON m.definition_id=d.id WHERE d.id=?`), version.DefinitionID).Scan(&agentKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDefinitionNotFound
		}
		return fmt.Errorf("check catalog definition for version: %w", err)
	}
	var manifest agentManifest
	if err := json.Unmarshal(version.Manifest, &manifest); err != nil || manifest.AgentID != agentKey {
		return ErrAgentMismatch
	}
	created := version.CreatedAt
	if created.IsZero() || actor != nil {
		created = s.clock()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create catalog version: %w", err)
	}
	defer tx.Rollback()
	if actor != nil {
		if err := s.beginRelease(ctx, tx, *actor, ControlSubmit); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_version
		(id,definition_id,semantic_version,manifest_hash,artifact_digest,input_schema,output_schema,status,revision,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`), version.ID, version.DefinitionID, version.SemanticVersion,
		version.ManifestHash, version.ArtifactDigest, string(version.InputSchema), string(version.OutputSchema),
		version.Status, version.Revision, created)
	if err != nil {
		return fmt.Errorf("create catalog version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_version_artifact (version_id,manifest_json,input_schema_json,output_schema_json,created_at) VALUES (?,?,?,?,?)`), version.ID, version.Manifest, version.InputSchema, version.OutputSchema, created); err != nil {
		return fmt.Errorf("create catalog version artifact: %w", err)
	}
	if actor != nil {
		if err := s.recordSubmission(ctx, tx, "version", version.ID, *actor, created); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit catalog version: %w", err)
	}
	return nil
}

func (s *SQLStore) GetVersion(ctx context.Context, id string) (Version, error) {
	var row Version
	var evaluated, published sql.NullTime
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.id,v.definition_id,v.semantic_version,v.manifest_hash,v.artifact_digest,a.manifest_json,a.input_schema_json,a.output_schema_json,v.status,v.revision,v.created_at,v.evaluated_at,v.published_at,COALESCE(p.submitted_by,''),COALESCE(p.approved_by,'')
		FROM platform_catalog_version v JOIN platform_catalog_version_artifact a ON a.version_id=v.id LEFT JOIN platform_catalog_submission p ON p.object_kind='version' AND p.object_id=v.id WHERE v.id=?`), id).
		Scan(&row.ID, &row.DefinitionID, &row.SemanticVersion, &row.ManifestHash, &row.ArtifactDigest, &row.Manifest, &row.InputSchema, &row.OutputSchema, &row.Status, &row.Revision, &row.CreatedAt, &evaluated, &published, &row.SubmittedBy, &row.ApprovedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrVersionNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("get catalog version: %w", err)
	}
	if evaluated.Valid {
		row.EvaluatedAt = &evaluated.Time
	}
	if published.Valid {
		row.PublishedAt = &published.Time
	}
	return row, nil
}

func (s *SQLStore) ListVersions(ctx context.Context, definitionID string, limit int) ([]Version, error) {
	if strings.TrimSpace(definitionID) == "" || limit <= 0 || limit > 100 {
		return nil, ErrInvalidVersion
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT v.id,v.definition_id,v.semantic_version,v.manifest_hash,v.artifact_digest,a.manifest_json,a.input_schema_json,a.output_schema_json,v.status,v.revision,v.created_at,v.evaluated_at,v.published_at,COALESCE(p.submitted_by,''),COALESCE(p.approved_by,'')
		FROM platform_catalog_version v JOIN platform_catalog_version_artifact a ON a.version_id=v.id LEFT JOIN platform_catalog_submission p ON p.object_kind='version' AND p.object_id=v.id
		WHERE v.definition_id=? ORDER BY v.created_at DESC,v.id ASC LIMIT ?`), definitionID, limit)
	if err != nil {
		return nil, fmt.Errorf("list catalog versions: %w", err)
	}
	defer rows.Close()
	items := make([]Version, 0)
	for rows.Next() {
		var item Version
		var evaluated, published sql.NullTime
		if err := rows.Scan(&item.ID, &item.DefinitionID, &item.SemanticVersion, &item.ManifestHash, &item.ArtifactDigest, &item.Manifest, &item.InputSchema, &item.OutputSchema, &item.Status, &item.Revision, &item.CreatedAt, &evaluated, &published, &item.SubmittedBy, &item.ApprovedBy); err != nil {
			return nil, fmt.Errorf("scan catalog version: %w", err)
		}
		if evaluated.Valid {
			item.EvaluatedAt = &evaluated.Time
		}
		if published.Valid {
			item.PublishedAt = &published.Time
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate catalog versions: %w", err)
	}
	return items, nil
}

func (s *SQLStore) ListPublishedDefinitions(ctx context.Context, limit int) ([]Definition, error) {
	if limit <= 0 || limit > 100 {
		return nil, ErrInvalidDefinition
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT d.id,d.publisher_id,d.agent_key,d.display_name,m.description,d.status,d.revision
		FROM platform_catalog_definition d JOIN platform_catalog_definition_metadata m ON m.definition_id=d.id
		WHERE d.status=? ORDER BY d.created_at DESC,d.id ASC LIMIT ?`), DefinitionPublished, limit)
	if err != nil {
		return nil, fmt.Errorf("list published catalog definitions: %w", err)
	}
	defer rows.Close()
	items := make([]Definition, 0)
	for rows.Next() {
		var item Definition
		if err := rows.Scan(&item.ID, &item.PublisherID, &item.AgentKey, &item.DisplayName, &item.Description, &item.Status, &item.Revision); err != nil {
			return nil, fmt.Errorf("scan published catalog definition: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate published catalog definitions: %w", err)
	}
	return items, nil
}

func (s *SQLStore) ListPublishedVersions(ctx context.Context, definitionID string, limit int) ([]PublishedVersion, error) {
	if strings.TrimSpace(definitionID) == "" || limit <= 0 || limit > 100 {
		return nil, ErrInvalidVersion
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT v.id,v.definition_id,v.semantic_version,v.manifest_hash,v.artifact_digest,v.status,v.revision
		FROM platform_catalog_version v JOIN platform_catalog_definition d ON d.id=v.definition_id
		WHERE v.definition_id=? AND d.status=? AND v.status=? ORDER BY v.created_at DESC,v.id ASC LIMIT ?`), definitionID, DefinitionPublished, DefinitionPublished, limit)
	if err != nil {
		return nil, fmt.Errorf("list published catalog versions: %w", err)
	}
	defer rows.Close()
	items := make([]PublishedVersion, 0)
	for rows.Next() {
		var item PublishedVersion
		if err := rows.Scan(&item.ID, &item.DefinitionID, &item.SemanticVersion, &item.ManifestHash, &item.ArtifactDigest, &item.Status, &item.Revision); err != nil {
			return nil, fmt.Errorf("scan published catalog version: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate published catalog versions: %w", err)
	}
	return items, nil
}

func (s *SQLStore) TransitionVersion(ctx context.Context, id string, from, to DefinitionStatus, expectedRevision uint64) error {
	if strings.TrimSpace(id) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	if from != DefinitionDraft && from != DefinitionEvaluated {
		return ErrIllegalTransition
	}
	if (from == DefinitionDraft && to != DefinitionEvaluated) || (from == DefinitionEvaluated && to != DefinitionPublished) {
		return ErrIllegalTransition
	}
	now := s.clock()
	set := "status=?, revision=revision+1"
	args := []any{to}
	if to == DefinitionEvaluated {
		set += ", evaluated_at=?"
		args = append(args, now)
	} else {
		set += ", published_at=?"
		args = append(args, now)
	}
	args = append(args, id, from, expectedRevision, id)
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_version SET `+set+` WHERE id=? AND status=? AND revision=? AND EXISTS (SELECT 1 FROM platform_catalog_version_artifact WHERE version_id=?)`), args...)
	if err != nil {
		return fmt.Errorf("transition catalog version: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("transition catalog version rows: %w", err)
	}
	if rows != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func (s *SQLStore) CreateInstallation(ctx context.Context, installation Installation) error {
	if err := installation.Validate(); err != nil {
		return ErrInvalidInstallation
	}
	if installation.Status != InstallationProvisioning || installation.Revision != 1 {
		return ErrInvalidInstallation
	}
	var versionStatus, definitionStatus DefinitionStatus
	var agentKey string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.status,d.agent_key,d.status
		FROM platform_catalog_version v JOIN platform_catalog_version_artifact va ON va.version_id=v.id
		JOIN platform_catalog_definition d ON d.id=v.definition_id JOIN platform_catalog_definition_metadata dm ON dm.definition_id=d.id
		WHERE v.id=?`), installation.VersionID).Scan(&versionStatus, &agentKey, &definitionStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return fmt.Errorf("check catalog installation version: %w", err)
	}
	if versionStatus != DefinitionPublished {
		return ErrVersionNotPublished
	}
	if definitionStatus != DefinitionPublished {
		return ErrDefinitionNotPublished
	}
	if agentKey != installation.AgentID {
		return ErrAgentMismatch
	}
	now := s.clock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create catalog installation: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_installation
		(id,tenant_id,department_id,application_id,agent_id,version_id,status,revision,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`), installation.ID, installation.TenantID, installation.DepartmentID,
		installation.ApplicationID, installation.AgentID, installation.VersionID, installation.Status,
		installation.Revision, now, now)
	if err != nil {
		return catalogPersistenceError("create catalog installation", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_installation_options (installation_id,display_name,deployment_mode,drain_policy,retention_policy_id,created_at) VALUES (?,?,?,?,?,?)`), installation.ID, installation.DisplayName, installation.DeploymentMode, installation.DrainPolicy, installation.RetentionPolicyID, now); err != nil {
		return catalogPersistenceError("create catalog installation options", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit catalog installation: %w", err)
	}
	return nil
}

func (s *SQLStore) GetInstallation(ctx context.Context, id string) (Installation, error) {
	var row Installation
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT i.id,i.tenant_id,i.department_id,i.application_id,i.agent_id,i.version_id,o.display_name,o.deployment_mode,o.drain_policy,o.retention_policy_id,i.status,i.revision
		FROM platform_catalog_installation i JOIN platform_catalog_installation_options o ON o.installation_id=i.id WHERE i.id=?`), id).
		Scan(&row.ID, &row.TenantID, &row.DepartmentID, &row.ApplicationID, &row.AgentID, &row.VersionID, &row.DisplayName, &row.DeploymentMode, &row.DrainPolicy, &row.RetentionPolicyID, &row.Status, &row.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Installation{}, ErrInstallationNotFound
	}
	if err != nil {
		return Installation{}, fmt.Errorf("get catalog installation: %w", err)
	}
	return row, nil
}

func (s *SQLStore) ListInstallations(ctx context.Context, tenantID, departmentID, applicationID string, limit int) ([]Installation, error) {
	if strings.TrimSpace(tenantID) == "" || limit <= 0 || limit > 100 {
		return nil, ErrInvalidInstallation
	}
	conditions := []string{"i.tenant_id=?"}
	args := []any{tenantID}
	if departmentID = strings.TrimSpace(departmentID); departmentID != "" {
		conditions = append(conditions, "i.department_id=?")
		args = append(args, departmentID)
	}
	if applicationID = strings.TrimSpace(applicationID); applicationID != "" {
		conditions = append(conditions, "i.application_id=?")
		args = append(args, applicationID)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT i.id,i.tenant_id,i.department_id,i.application_id,i.agent_id,i.version_id,o.display_name,o.deployment_mode,o.drain_policy,o.retention_policy_id,i.status,i.revision
		FROM platform_catalog_installation i JOIN platform_catalog_installation_options o ON o.installation_id=i.id
		WHERE `+strings.Join(conditions, " AND ")+`
		ORDER BY i.created_at DESC,i.id ASC LIMIT ?`), args...)
	if err != nil {
		return nil, fmt.Errorf("list catalog installations: %w", err)
	}
	defer rows.Close()
	items := make([]Installation, 0)
	for rows.Next() {
		var item Installation
		if err := rows.Scan(&item.ID, &item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.AgentID, &item.VersionID, &item.DisplayName, &item.DeploymentMode, &item.DrainPolicy, &item.RetentionPolicyID, &item.Status, &item.Revision); err != nil {
			return nil, fmt.Errorf("scan catalog installation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate catalog installations: %w", err)
	}
	return items, nil
}

// ListAvailableAgents returns only active installations of published
// definitions and versions within the exact authenticated application scope.
// ListAvailableAgents 仅返回可信应用作用域中已发布 Definition/Version 的活动安装。
func (s *SQLStore) ListAvailableAgents(ctx context.Context, tenantID, departmentID, applicationID string) ([]AvailableAgent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("catalog database is required")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(departmentID) == "" || strings.TrimSpace(applicationID) == "" {
		return nil, errors.New("catalog application scope is required")
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT d.agent_key,d.display_name,v.semantic_version,v.id,i.id
		FROM platform_catalog_installation i
		JOIN platform_catalog_installation_options io ON io.installation_id=i.id
		JOIN platform_catalog_definition d ON d.agent_key=i.agent_id AND d.status=?
		JOIN platform_catalog_definition_metadata dm ON dm.definition_id=d.id
		JOIN platform_catalog_version v ON v.id=i.version_id AND v.definition_id=d.id AND v.status=?
		JOIN platform_catalog_version_artifact va ON va.version_id=v.id
		WHERE i.tenant_id=? AND i.department_id=? AND i.application_id=? AND i.status=?
		ORDER BY d.agent_key,v.semantic_version DESC,i.id`), DefinitionPublished, DefinitionPublished, tenantID, departmentID, applicationID, InstallationActive)
	if err != nil {
		return nil, fmt.Errorf("list available catalog agents: %w", err)
	}
	defer rows.Close()
	items := make([]AvailableAgent, 0)
	for rows.Next() {
		var item AvailableAgent
		if err := rows.Scan(&item.AgentID, &item.Name, &item.SemanticVersion, &item.VersionID, &item.InstallationID); err != nil {
			return nil, fmt.Errorf("scan available catalog agent: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate available catalog agents: %w", err)
	}
	return items, nil
}

func (s *SQLStore) TransitionInstallation(ctx context.Context, id string, from, to InstallationStatus, expectedRevision uint64) error {
	if err := ValidateInstallationTransition(from, to); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	query := `UPDATE platform_catalog_installation AS i
		SET status=?, revision=revision+1, updated_at=?
		WHERE i.id=? AND i.status=? AND i.revision=? AND EXISTS (SELECT 1 FROM platform_catalog_installation_options WHERE installation_id=i.id)`
	args := []any{to, s.clock(), id, from, expectedRevision}
	if to == InstallationActive {
		// Activation is fenced in the same CAS statement by the latest observed
		// deployment for the installation's currently selected version. A health
		// result for an older deployment revision cannot open the newer release.
		// 激活在同一 CAS SQL 中要求当前 Version 的最新部署已观测为 Ready；旧 revision 的健康结果不能开启新发布。
		query += ` AND EXISTS (
			SELECT 1 FROM platform_catalog_deployment d
			WHERE d.agent_installation_id=i.id AND d.tenant_id=i.tenant_id
			AND d.department_id=i.department_id AND d.application_id=i.application_id
			AND d.agent_version_id=i.version_id AND d.status=?
			AND d.observed_revision=d.desired_revision
			AND d.desired_revision=(SELECT MAX(d2.desired_revision) FROM platform_catalog_deployment d2
				WHERE d2.agent_installation_id=i.id AND d2.tenant_id=i.tenant_id
				AND d2.department_id=i.department_id AND d2.application_id=i.application_id)
		)`
		args = append(args, DeploymentReady)
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return fmt.Errorf("transition catalog installation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("transition catalog installation rows: %w", err)
	}
	if rows != 1 {
		if to == InstallationActive {
			var status InstallationStatus
			var revision uint64
			readErr := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,revision FROM platform_catalog_installation WHERE id=?`), id).Scan(&status, &revision)
			if errors.Is(readErr, sql.ErrNoRows) {
				return ErrInstallationNotFound
			}
			if readErr != nil {
				return fmt.Errorf("read catalog installation after failed activation: %w", readErr)
			}
			if status == from && revision == expectedRevision {
				return ErrDeploymentNotReady
			}
		}
		return ErrRevisionConflict
	}
	return nil
}

// RollbackInstallation switches an installation to an already published
// version with one optimistic-concurrency update. It never mutates a version
// or silently changes the installation scope.
// RollbackInstallation 只在一次 CAS 更新中切换到已发布版本，不修改版本内容，也不改变安装作用域。
func (s *SQLStore) RollbackInstallation(ctx context.Context, id, versionID string, expectedRevision uint64) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(versionID) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	var status DefinitionStatus
	var targetAgent string
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.status,d.agent_key
		FROM platform_catalog_version v JOIN platform_catalog_version_artifact va ON va.version_id=v.id
		JOIN platform_catalog_definition d ON d.id=v.definition_id JOIN platform_catalog_definition_metadata dm ON dm.definition_id=d.id WHERE v.id=?`), versionID).Scan(&status, &targetAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVersionNotFound
		}
		return fmt.Errorf("check rollback version: %w", err)
	}
	if status != DefinitionPublished {
		return ErrVersionNotPublished
	}
	var currentAgent string
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT i.agent_id FROM platform_catalog_installation i JOIN platform_catalog_installation_options o ON o.installation_id=i.id WHERE i.id=?`), id).Scan(&currentAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInstallationNotFound
		}
		return fmt.Errorf("check rollback installation: %w", err)
	}
	if currentAgent != targetAgent {
		return ErrAgentMismatch
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_installation
		SET version_id=?, revision=revision+1, updated_at=?
		WHERE id=? AND status IN (?,?) AND revision=? AND EXISTS (SELECT 1 FROM platform_catalog_installation_options WHERE installation_id=?) AND EXISTS (SELECT 1 FROM platform_catalog_version_artifact WHERE version_id=?)`), versionID, s.clock(), id, InstallationActive, InstallationSuspended, expectedRevision, id, versionID)
	if err != nil {
		return fmt.Errorf("rollback catalog installation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rollback catalog installation rows: %w", err)
	}
	if rows != 1 {
		return ErrRevisionConflict
	}
	return nil
}

// UninstallInstallation starts the uninstall lifecycle with a CAS fence. A
// separate transition to uninstalled is intentional: the deployment worker
// must be able to drain/cleanup before the catalog records terminal state.
func (s *SQLStore) UninstallInstallation(ctx context.Context, id string, expectedRevision uint64) error {
	if strings.TrimSpace(id) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_installation
		SET status=?, revision=revision+1, updated_at=?
		WHERE id=? AND status IN (?,?,?) AND revision=? AND EXISTS (SELECT 1 FROM platform_catalog_installation_options WHERE installation_id=?)`), InstallationUninstalling, s.clock(), id,
		InstallationActive, InstallationSuspended, InstallationDraining, expectedRevision, id)
	if err != nil {
		return fmt.Errorf("uninstall catalog installation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("uninstall catalog installation rows: %w", err)
	}
	if rows != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func validDeploymentEndpoint(raw, transport string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	allowed := map[string]string{"http": "http", "https": "http", "grpc": "grpc", "grpcs": "grpc"}
	return allowed[strings.ToLower(u.Scheme)] == transport
}

// CreateDeployment records a desired deployment revision against the version
// currently selected by an installation. Revision allocation is serialized by
// locking the installation row; a stale caller-supplied revision returns a
// stable conflict instead of creating an invalid deployment.
// CreateDeployment 只为安装当前选定的版本登记期望部署；通过锁定安装行串行分配 Revision，
// 过期的调用方 Revision 返回稳定冲突，不会落入无效 Deployment。
func (s *SQLStore) CreateDeployment(ctx context.Context, deployment Deployment) (Deployment, error) {
	if s == nil || s.db == nil {
		return Deployment{}, errors.New("catalog database is required")
	}
	if deployment.Status == "" {
		deployment.Status = DeploymentPending
	}
	requestedRevision := deployment.DesiredRevision
	if deployment.ObservedRevision != 0 || !validDeploymentEndpoint(deployment.EndpointRef, deployment.Transport) {
		return Deployment{}, ErrInvalidDeployment
	}
	if deployment.DesiredRevision == 0 {
		deployment.DesiredRevision = 1 // Model validation placeholder; the actual revision is allocated below. / 模型校验占位值，实际 Revision 在下方分配。
	}
	if err := deployment.Validate(); err != nil {
		return Deployment{}, err
	}
	deployment.DesiredRevision = requestedRevision
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Deployment{}, fmt.Errorf("begin create catalog deployment: %w", err)
	}
	defer tx.Rollback()
	// Serialize revision allocation against the installation row. This prevents
	// parallel rollout requests from both observing the same MAX()+1 value, and
	// makes activation's readiness CAS order cleanly before or after a rollout.
	// 锁定安装行后分配 revision，串行化并发发布请求，并与激活 CAS 建立明确顺序。
	var currentVersion string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT i.version_id FROM platform_catalog_installation i
		JOIN platform_catalog_installation_options io ON io.installation_id=i.id
		WHERE i.id=? AND i.tenant_id=? AND i.department_id=? AND i.application_id=? FOR UPDATE`), deployment.AgentInstallationID, deployment.TenantID, deployment.DepartmentID, deployment.ApplicationID).Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrInstallationNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("lock catalog installation for deployment: %w", err)
	}
	if deployment.AgentVersionID != currentVersion {
		return Deployment{}, ErrDeploymentVersionMismatch
	}
	var nextRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COALESCE(MAX(desired_revision),0)+1 FROM platform_catalog_deployment WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_installation_id=?`), deployment.TenantID, deployment.DepartmentID, deployment.ApplicationID, deployment.AgentInstallationID).Scan(&nextRevision); err != nil {
		return Deployment{}, fmt.Errorf("allocate catalog deployment revision: %w", err)
	}
	if requestedRevision != 0 && requestedRevision != nextRevision {
		return Deployment{}, ErrCatalogConflict
	}
	deployment.DesiredRevision = nextRevision
	if err := deployment.Validate(); err != nil {
		return Deployment{}, err
	}
	var agentID string
	var versionStatus DefinitionStatus
	var artifactDigest, manifestHash, catalogAgent string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT i.agent_id,v.status,v.artifact_digest,v.manifest_hash,d.agent_key
		FROM platform_catalog_installation i
		JOIN platform_catalog_installation_options io ON io.installation_id=i.id
		JOIN platform_catalog_version v ON v.id=?
		JOIN platform_catalog_version_artifact va ON va.version_id=v.id
		JOIN platform_catalog_definition d ON d.id=v.definition_id JOIN platform_catalog_definition_metadata dm ON dm.definition_id=d.id
		WHERE i.id=? AND i.tenant_id=? AND i.department_id=? AND i.application_id=?`), deployment.AgentVersionID, deployment.AgentInstallationID, deployment.TenantID, deployment.DepartmentID, deployment.ApplicationID).
		Scan(&agentID, &versionStatus, &artifactDigest, &manifestHash, &catalogAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return Deployment{}, ErrInstallationNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("check catalog deployment references: %w", err)
	}
	if versionStatus != DefinitionPublished || agentID != catalogAgent || artifactDigest != deployment.ArtifactDigest || manifestHash != deployment.ManifestHash {
		return Deployment{}, ErrVersionNotPublished
	}
	now := s.clock()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_deployment
		(id,tenant_id,department_id,application_id,agent_version_id,agent_installation_id,artifact_digest,transport,endpoint_ref,placement_policy,resource_policy,status,desired_revision,observed_revision,manifest_hash,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), deployment.ID, deployment.TenantID, deployment.DepartmentID, deployment.ApplicationID, deployment.AgentVersionID, deployment.AgentInstallationID, deployment.ArtifactDigest, deployment.Transport, deployment.EndpointRef, deployment.PlacementPolicy, deployment.ResourcePolicy, deployment.Status, deployment.DesiredRevision, deployment.ObservedRevision, deployment.ManifestHash, now, now)
	if err != nil {
		return Deployment{}, catalogPersistenceError("create catalog deployment", err)
	}
	if err := tx.Commit(); err != nil {
		return Deployment{}, fmt.Errorf("commit catalog deployment: %w", err)
	}
	deployment.CreatedAt, deployment.UpdatedAt = now, now
	return deployment, nil
}

func (s *SQLStore) ListDeployments(ctx context.Context, tenantID, departmentID, applicationID, installationID string, limit int) ([]Deployment, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT d.id,d.tenant_id,d.department_id,d.application_id,d.agent_version_id,d.agent_installation_id,d.artifact_digest,d.transport,d.endpoint_ref,d.placement_policy,d.resource_policy,d.status,d.desired_revision,d.observed_revision,d.manifest_hash,d.created_at,d.updated_at
		FROM platform_catalog_deployment d JOIN platform_catalog_installation_options io ON io.installation_id=d.agent_installation_id
		JOIN platform_catalog_version_artifact va ON va.version_id=d.agent_version_id
		WHERE d.tenant_id=? AND d.department_id=? AND d.application_id=? AND d.agent_installation_id=? ORDER BY d.desired_revision DESC LIMIT ?`), tenantID, departmentID, applicationID, installationID, limit)
	if err != nil {
		return nil, fmt.Errorf("list catalog deployments: %w", err)
	}
	defer rows.Close()
	var result []Deployment
	for rows.Next() {
		var row Deployment
		if err := rows.Scan(&row.ID, &row.TenantID, &row.DepartmentID, &row.ApplicationID, &row.AgentVersionID, &row.AgentInstallationID, &row.ArtifactDigest, &row.Transport, &row.EndpointRef, &row.PlacementPolicy, &row.ResourcePolicy, &row.Status, &row.DesiredRevision, &row.ObservedRevision, &row.ManifestHash, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan catalog deployment: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate catalog deployments: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ObserveDeployment(ctx context.Context, tenantID, departmentID, applicationID, installationID, id string, desiredRevision uint64, status DeploymentStatus) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(departmentID) == "" || strings.TrimSpace(applicationID) == "" || strings.TrimSpace(installationID) == "" || strings.TrimSpace(id) == "" || desiredRevision == 0 || !validDeploymentStatus(status) {
		return ErrRevisionConflict
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_deployment SET observed_revision=?,status=?,updated_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND agent_installation_id=? AND desired_revision=? AND observed_revision<? AND EXISTS (SELECT 1 FROM platform_catalog_installation_options WHERE installation_id=?)`), desiredRevision, status, s.clock(), id, tenantID, departmentID, applicationID, installationID, desiredRevision, desiredRevision, installationID)
	if err != nil {
		return fmt.Errorf("observe catalog deployment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("observe catalog deployment rows: %w", err)
	}
	if rows != 1 {
		return ErrCatalogConflict
	}
	return nil
}

var _ Store = (*SQLStore)(nil)
