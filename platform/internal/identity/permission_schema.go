package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
)

// EnsurePermissionSchema is called only by the explicit migration command.
// The directory seeds are immutable definitions, never user assignments.
func (s *SQLStore) EnsurePermissionSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_role_definition (role_code VARCHAR(64) NOT NULL,role_version NUMERIC(20,0) CHECK (role_version>=0 AND role_version<=18446744073709551615) NOT NULL,payload JSON NOT NULL,content_hash VARCHAR(64) NOT NULL,PRIMARY KEY(role_code,role_version));
`,
		`CREATE TABLE IF NOT EXISTS platform_identity_preset_definition (preset_code VARCHAR(64) NOT NULL,preset_version NUMERIC(20,0) CHECK (preset_version>=0 AND preset_version<=18446744073709551615) NOT NULL,payload JSON NOT NULL,content_hash VARCHAR(64) NOT NULL,PRIMARY KEY(preset_code,preset_version));
`,
		`CREATE TABLE IF NOT EXISTS platform_identity_policy_migration (principal_type VARCHAR(32) NOT NULL,subject_id VARCHAR(128) NOT NULL,policy_mode VARCHAR(16) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,epoch NUMERIC(20,0) CHECK (epoch>=0 AND epoch<=18446744073709551615) NOT NULL,batch_id VARCHAR(128) NOT NULL DEFAULT '',source_digest VARCHAR(64) NOT NULL DEFAULT '',PRIMARY KEY(principal_type,subject_id));
`,
		`CREATE TABLE IF NOT EXISTS platform_identity_membership (id VARCHAR(128) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,starts_at TIMESTAMPTZ(6) NULL,expires_at TIMESTAMPTZ(6) NULL,payload JSON NOT NULL,scope_hash VARCHAR(64) NOT NULL,CONSTRAINT uq_membership_scope UNIQUE(scope_hash));
CREATE INDEX IF NOT EXISTS idx_membership_subject ON platform_identity_membership (subject_id,status);
CREATE INDEX IF NOT EXISTS idx_membership_directory ON platform_identity_membership (tenant_id,department_id,application_id,status,subject_id);
DROP INDEX IF EXISTS idx_membership_scope;`,
		`CREATE TABLE IF NOT EXISTS platform_identity_role_binding (id VARCHAR(128) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,role_code VARCHAR(64) NOT NULL,role_version NUMERIC(20,0) CHECK (role_version>=0 AND role_version<=18446744073709551615) NOT NULL,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,starts_at TIMESTAMPTZ(6) NULL,expires_at TIMESTAMPTZ(6) NULL,payload JSON NOT NULL,source_hash VARCHAR(64) NOT NULL,CONSTRAINT uq_binding_source UNIQUE(source_hash));
CREATE INDEX IF NOT EXISTS idx_binding_subject ON platform_identity_role_binding (subject_id,status);
CREATE INDEX IF NOT EXISTS idx_binding_scope ON platform_identity_role_binding (tenant_id,department_id,application_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_delegation (id VARCHAR(128) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,status VARCHAR(24) NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,starts_at TIMESTAMPTZ(6) NULL,expires_at TIMESTAMPTZ(6) NULL,payload JSON NOT NULL);
CREATE INDEX IF NOT EXISTS idx_delegation_subject ON platform_identity_delegation (subject_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_authorization_change (id VARCHAR(128) PRIMARY KEY,actor_id VARCHAR(128) NOT NULL,subject_id VARCHAR(128) NOT NULL,idempotency_hash VARCHAR(64) NOT NULL,request_digest VARCHAR(64) NOT NULL,receipt JSON NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL,CONSTRAINT uq_change_retry UNIQUE(idempotency_hash));
CREATE INDEX IF NOT EXISTS idx_change_subject ON platform_identity_authorization_change (subject_id,created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_continuity_guard (id INT PRIMARY KEY,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL);
`,
		`INSERT INTO platform_identity_continuity_guard(id,revision) VALUES(1,1) ON CONFLICT (id) DO UPDATE SET id=platform_identity_continuity_guard.id`,
	}
	for _, ddl := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(ddl)); err != nil {
			return fmt.Errorf("permission schema: %w", err)
		}
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM information_schema.columns WHERE TABLE_SCHEMA=current_schema() AND TABLE_NAME='platform_identity_grant' AND COLUMN_NAME='permission_json'`)).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`ALTER TABLE platform_identity_grant ADD COLUMN permission_json JSON NULL`)); err != nil {
			return err
		}
	}
	for _, role := range BuiltinRoleDefinitions() {
		if err := seedPermissionDirectory(ctx, s.db, "role", role.Code, role.Version, role); err != nil {
			return err
		}
	}
	for _, preset := range BuiltinIdentityPresets() {
		if err := seedPermissionDirectory(ctx, s.db, "preset", preset.Code, preset.Version, preset); err != nil {
			return err
		}
	}
	if err := s.EnsureDepartmentAgentPackageSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureDepartmentAgentAccessSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsurePermissionBatchSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureRefreshSessionSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureStepUpSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsurePermissionRequestSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureTaskAssignmentSchema(ctx); err != nil {
		return err
	}
	if err := s.EnsureOIDCStepUpSchema(ctx); err != nil {
		return err
	}
	return s.EnsureWorkloadBindingSchema(ctx)
}

func seedPermissionDirectory(ctx context.Context, db sqlutil.SchemaWriter, kind, code string, version uint64, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := permissionHash(raw)
	var insert, read string
	switch kind {
	case "role":
		insert = `INSERT INTO platform_identity_role_definition(role_code,role_version,payload,content_hash) VALUES(?,?,?,?) ON CONFLICT (role_code,role_version) DO UPDATE SET role_code=platform_identity_role_definition.role_code`
		read = `SELECT content_hash FROM platform_identity_role_definition WHERE role_code=? AND role_version=?`
	case "preset":
		insert = `INSERT INTO platform_identity_preset_definition(preset_code,preset_version,payload,content_hash) VALUES(?,?,?,?) ON CONFLICT (preset_code,preset_version) DO UPDATE SET preset_code=platform_identity_preset_definition.preset_code`
		read = `SELECT content_hash FROM platform_identity_preset_definition WHERE preset_code=? AND preset_version=?`
	default:
		return ErrInvalidResource
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(insert), code, version, string(raw), digest); err != nil {
		return err
	}
	var stored string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(read), code, version).Scan(&stored); err != nil {
		return err
	}
	if stored != digest {
		return fmt.Errorf("immutable %s definition %s/%d differs; publish a new version", kind, code, version)
	}
	return nil
}

func (s *SQLStore) PublishPermissionDirectory(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	return sqlutil.WithSchemaTransaction(ctx, s.db, func(tx sqlutil.SchemaWriter) error {
		for _, role := range BuiltinRoleDefinitions() {
			if err := seedPermissionDirectory(ctx, tx, "role", role.Code, role.Version, role); err != nil {
				return err
			}
		}
		for _, preset := range BuiltinIdentityPresets() {
			if err := seedPermissionDirectory(ctx, tx, "preset", preset.Code, preset.Version, preset); err != nil {
				return err
			}
		}
		return nil
	})
}
