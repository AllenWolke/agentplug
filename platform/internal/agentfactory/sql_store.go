package agentfactory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"time"
)

// SQLStore owns the PostgreSQL records for Agent Factory. It uses the same Store port in-process or behind a future service adapter.
// SQLStore 拥有 Agent Factory 的 PostgreSQL 记录；本地单体和未来远程 Adapter 使用相同 Store 端口。
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("agent factory database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_agent_template (
			id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			scope_hash VARCHAR(64) NOT NULL,
			template_id VARCHAR(128) NOT NULL,
			name VARCHAR(128) NOT NULL,
			language VARCHAR(16) NOT NULL,
			framework VARCHAR(64) NOT NULL,
			status VARCHAR(24) NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_agent_template_scope_key UNIQUE (scope_hash,template_id));
CREATE INDEX IF NOT EXISTS idx_agent_template_scope_created ON platform_agent_template (scope_hash,created_at,id);`,
		`CREATE TABLE IF NOT EXISTS platform_agent_template_version (
			id VARCHAR(36) PRIMARY KEY,
			scope_hash VARCHAR(64) NOT NULL,
			definition_id VARCHAR(36) NOT NULL,
			semantic_version VARCHAR(64) NOT NULL,
			artifact_uri VARCHAR(512) NOT NULL,
			content_hash VARCHAR(64) NOT NULL,
			lock_hash VARCHAR(64) NOT NULL,
			artifact_size BIGINT CHECK (artifact_size>=0 AND artifact_size<=4294967295) NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_agent_template_version_semver UNIQUE (scope_hash,definition_id,semantic_version));
CREATE INDEX IF NOT EXISTS idx_agent_template_version_parent ON platform_agent_template_version (scope_hash,definition_id,created_at,id);`,
		`CREATE TABLE IF NOT EXISTS platform_agent_mapping (
			id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			scope_hash VARCHAR(64) NOT NULL,
			mapping_id VARCHAR(128) NOT NULL,
			kind VARCHAR(24) NOT NULL,
			status VARCHAR(24) NOT NULL,
			spec_json JSON NOT NULL,
			content_hash VARCHAR(64) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (scope_hash,id),
			CONSTRAINT uq_agent_mapping_scope_key UNIQUE (scope_hash,mapping_id));
CREATE INDEX IF NOT EXISTS idx_agent_mapping_scope_created ON platform_agent_mapping (scope_hash,created_at,id);`,
		`CREATE TABLE IF NOT EXISTS platform_agent_mapping_evidence (
			id VARCHAR(36) PRIMARY KEY,
			scope_hash VARCHAR(64) NOT NULL,
			mapping_id VARCHAR(128) NOT NULL,
			mapping_revision NUMERIC(20,0) CHECK (mapping_revision>=0 AND mapping_revision<=18446744073709551615) NOT NULL,
			mapping_hash VARCHAR(64) NOT NULL,
			fixture_hash VARCHAR(64) NOT NULL,
			result_hash VARCHAR(64) NOT NULL,
			status VARCHAR(16) NOT NULL,
			check_count BIGINT CHECK (check_count>=0 AND check_count<=4294967295) NOT NULL,
			created_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_agent_mapping_evidence_current ON platform_agent_mapping_evidence (scope_hash,mapping_id,mapping_revision,mapping_hash,status,created_at);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("agent factory schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("agent factory database is required")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLStore) CreateTemplate(ctx context.Context, row Template) error {
	if row.Scope.Validate() != nil || row.ID == "" || row.TemplateID == "" {
		return ErrInvalidRequest
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_template
		(id,tenant_id,department_id,application_id,scope_hash,template_id,name,language,framework,status,created_by,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.Scope.TenantID, row.Scope.DepartmentID, row.Scope.ApplicationID, scopeHash(row.Scope), row.TemplateID, row.Name, row.Language, row.Framework, row.Status, row.CreatedBy, row.CreatedAt, row.UpdatedAt)
	return mapDuplicate(err)
}

const templateColumns = `id,tenant_id,department_id,application_id,template_id,name,language,framework,status,created_by,created_at,updated_at`

func scanTemplate(row interface{ Scan(...any) error }) (Template, error) {
	var item Template
	err := row.Scan(&item.ID, &item.Scope.TenantID, &item.Scope.DepartmentID, &item.Scope.ApplicationID, &item.TemplateID, &item.Name, &item.Language, &item.Framework, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, mapNotFound(err)
}

func (s *SQLStore) GetTemplate(ctx context.Context, scope Scope, id string) (Template, error) {
	if scope.Validate() != nil {
		return Template{}, ErrInvalidScope
	}
	return scanTemplate(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+templateColumns+` FROM platform_agent_template WHERE scope_hash=? AND id=?`), scopeHash(scope), id))
}

func (s *SQLStore) ListTemplates(ctx context.Context, scope Scope, limit int, after string) ([]Template, error) {
	if scope.Validate() != nil {
		return nil, ErrInvalidScope
	}
	limit = clampLimit(limit)
	query := `SELECT ` + templateColumns + ` FROM platform_agent_template WHERE scope_hash=?`
	args := []any{scopeHash(scope)}
	if after != "" {
		query += ` AND id<?`
		args = append(args, after)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Template, 0)
	for rows.Next() {
		item, e := scanTemplate(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) CreateTemplateVersion(ctx context.Context, row TemplateVersion) error {
	if row.Scope.Validate() != nil || row.ID == "" || row.DefinitionID == "" || row.ContentHash == "" {
		return ErrInvalidRequest
	}
	// The parent check and insert share one transaction to prevent cross-scope/orphan versions.
	// 父模板检查和插入在同一事务中完成，避免跨作用域版本或孤儿版本。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_agent_template WHERE scope_hash=? AND id=? FOR UPDATE`), scopeHash(row.Scope), row.DefinitionID).Scan(&exists); err != nil {
		return mapNotFound(err)
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_template_version
		(id,scope_hash,definition_id,semantic_version,artifact_uri,content_hash,lock_hash,artifact_size,created_by,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`), row.ID, scopeHash(row.Scope), row.DefinitionID, row.SemanticVersion, row.ArtifactURI, row.ContentHash, row.LockHash, row.ArtifactSize, row.CreatedBy, row.CreatedAt)
	if err != nil {
		return mapDuplicate(err)
	}
	return tx.Commit()
}

const templateVersionColumns = `id,definition_id,semantic_version,artifact_uri,content_hash,lock_hash,artifact_size,created_by,created_at`

func scanTemplateVersion(row interface{ Scan(...any) error }, scope Scope) (TemplateVersion, error) {
	var item TemplateVersion
	item.Scope = scope
	err := row.Scan(&item.ID, &item.DefinitionID, &item.SemanticVersion, &item.ArtifactURI, &item.ContentHash, &item.LockHash, &item.ArtifactSize, &item.CreatedBy, &item.CreatedAt)
	return item, mapNotFound(err)
}
func (s *SQLStore) ListTemplateVersions(ctx context.Context, scope Scope, definitionID string, limit int) ([]TemplateVersion, error) {
	if scope.Validate() != nil {
		return nil, ErrInvalidScope
	}
	limit = clampLimit(limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT `+templateVersionColumns+` FROM platform_agent_template_version WHERE scope_hash=? AND definition_id=? ORDER BY created_at DESC,id DESC LIMIT ?`), scopeHash(scope), definitionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TemplateVersion, 0)
	for rows.Next() {
		item, e := scanTemplateVersion(rows, scope)
		if e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) CreateMapping(ctx context.Context, row Mapping) error {
	if row.Scope.Validate() != nil || row.ID == "" || row.ContentHash == "" || len(row.Spec) == 0 {
		return ErrInvalidRequest
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_mapping
		(id,tenant_id,department_id,application_id,scope_hash,mapping_id,kind,status,spec_json,content_hash,revision,created_by,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), row.ID, row.Scope.TenantID, row.Scope.DepartmentID, row.Scope.ApplicationID, scopeHash(row.Scope), row.MappingID, row.Kind, row.Status, string(row.Spec), row.ContentHash, row.Revision, row.CreatedBy, row.CreatedAt, row.UpdatedAt)
	return mapDuplicate(err)
}

const mappingColumns = `id,tenant_id,department_id,application_id,mapping_id,kind,status,spec_json,content_hash,revision,created_by,created_at,updated_at`

func scanMapping(row interface{ Scan(...any) error }) (Mapping, error) {
	var item Mapping
	var raw []byte
	err := row.Scan(&item.ID, &item.Scope.TenantID, &item.Scope.DepartmentID, &item.Scope.ApplicationID, &item.MappingID, &item.Kind, &item.Status, &raw, &item.ContentHash, &item.Revision, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	item.Spec = append(item.Spec[:0], raw...)
	return item, mapNotFound(err)
}
func (s *SQLStore) GetMapping(ctx context.Context, scope Scope, id string) (Mapping, error) {
	if scope.Validate() != nil {
		return Mapping{}, ErrInvalidScope
	}
	return scanMapping(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+mappingColumns+` FROM platform_agent_mapping WHERE scope_hash=? AND id=?`), scopeHash(scope), id))
}
func (s *SQLStore) ListMappings(ctx context.Context, scope Scope, limit int, after string) ([]Mapping, error) {
	if scope.Validate() != nil {
		return nil, ErrInvalidScope
	}
	limit = clampLimit(limit)
	query := `SELECT ` + mappingColumns + ` FROM platform_agent_mapping WHERE scope_hash=?`
	args := []any{scopeHash(scope)}
	if after != "" {
		query += ` AND id<?`
		args = append(args, after)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Mapping, 0)
	for rows.Next() {
		item, e := scanMapping(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) SaveEvidence(ctx context.Context, row ConformanceEvidence) error {
	if row.Scope.Validate() != nil || row.ID == "" || row.MappingID == "" || row.MappingHash == "" || row.FixtureHash == "" || row.Status != "passed" && row.Status != "failed" {
		return ErrInvalidRequest
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_agent_mapping_evidence(id,scope_hash,mapping_id,mapping_revision,mapping_hash,fixture_hash,result_hash,status,check_count,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), row.ID, scopeHash(row.Scope), row.MappingID, row.MappingRevision, row.MappingHash, row.FixtureHash, row.ResultHash, row.Status, row.CheckCount, row.CreatedBy, row.CreatedAt)
	return mapDuplicate(err)
}
func (s *SQLStore) ListEvidence(ctx context.Context, scope Scope, mappingID string, limit int) ([]ConformanceEvidence, error) {
	if scope.Validate() != nil {
		return nil, ErrInvalidScope
	}
	limit = clampLimit(limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,mapping_id,mapping_revision,mapping_hash,fixture_hash,result_hash,status,check_count,created_by,created_at FROM platform_agent_mapping_evidence WHERE scope_hash=? AND mapping_id=? ORDER BY created_at DESC,id DESC LIMIT ?`), scopeHash(scope), mappingID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ConformanceEvidence, 0)
	for rows.Next() {
		var item ConformanceEvidence
		item.Scope = scope
		if e := rows.Scan(&item.ID, &item.MappingID, &item.MappingRevision, &item.MappingHash, &item.FixtureHash, &item.ResultHash, &item.Status, &item.CheckCount, &item.CreatedBy, &item.CreatedAt); e != nil {
			return nil, e
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) PublishMapping(ctx context.Context, scope Scope, id string, expected uint64) (Mapping, error) {
	if scope.Validate() != nil {
		return Mapping{}, ErrInvalidScope
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Mapping{}, err
	}
	defer tx.Rollback()
	row, err := scanMapping(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT `+mappingColumns+` FROM platform_agent_mapping WHERE scope_hash=? AND id=? FOR UPDATE`), scopeHash(scope), id))
	if err != nil {
		return Mapping{}, err
	}
	if row.Status != StatusDraft || row.Revision != expected {
		return Mapping{}, ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_agent_mapping_evidence WHERE scope_hash=? AND mapping_id=? AND mapping_revision=? AND mapping_hash=? AND status='passed'`), scopeHash(scope), id, expected, row.ContentHash).Scan(&count); err != nil {
		return Mapping{}, err
	}
	if count == 0 {
		return Mapping{}, ErrConformanceNeeded
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_agent_mapping SET status=?,revision=revision+1,updated_at=? WHERE scope_hash=? AND id=? AND status=? AND revision=?`), StatusPublished, now, scopeHash(scope), id, StatusDraft, expected)
	if err != nil {
		return Mapping{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Mapping{}, err
	}
	if affected != 1 {
		return Mapping{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return Mapping{}, err
	}
	row.Status = StatusPublished
	row.Revision++
	row.UpdatedAt = now
	return row, nil
}

func scopeHash(scope Scope) string { return hashJSON(scope) }
func mapDuplicate(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "duplicate entry") || strings.Contains(message, "duplicate key") || strings.Contains(message, "unique constraint") {
		return ErrAlreadyExists
	}
	return err
}
func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

var _ Store = (*SQLStore)(nil)
