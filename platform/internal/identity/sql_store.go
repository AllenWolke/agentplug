package identity

// SQL persistence for the platform identity boundary.
// 平台身份边界的 SQL 持久化实现。

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrTenantNotFound                    = errors.New("identity tenant not found")
	ErrDepartmentNotFound                = errors.New("identity department not found")
	ErrApplicationNotFound               = errors.New("identity application not found")
	ErrPrincipalNotFound                 = errors.New("identity principal not found")
	ErrGrantNotFound                     = errors.New("identity grant not found")
	ErrIdentityConflict                  = errors.New("identity revision conflict")
	ErrAccessRequestNotFound             = errors.New("agent access request not found")
	ErrAccessRequestSelfReview           = errors.New("requester cannot review own agent access request")
	ErrAccessDecisionRecorderUnavailable = errors.New("agent access decision recorder is required")
	ErrInvalidOrganizationPage           = errors.New("invalid organization page")
)

type Store interface {
	EnsureSchema(context.Context) error
	Ping(context.Context) error
	CreateTenant(context.Context, Tenant) error
	CreateDepartment(context.Context, Department) error
	CreateApplication(context.Context, Application) error
	CreatePrincipal(context.Context, Principal) error
	GetPrincipal(context.Context, PrincipalType, string) (Principal, error)
	CreateGrant(context.Context, Grant) error
	ListGrants(context.Context, string, string, string, string, PrincipalType, string, string) ([]Grant, error)
}

// PrincipalLifecycleStore provides compare-and-set lifecycle changes for an
// identity principal. The implementation must invalidate every credential
// class in the same transaction as the Principal state change.
// PrincipalLifecycleStore 通过 CAS 修改主体状态，并要求同一事务失效所有凭据类型。
type PrincipalLifecycleStore interface {
	DisablePrincipal(context.Context, sharedkernel.Scope, string, uint64) (Principal, error)
}

// ReadStore is the read-only projection used by the identity HTTP boundary.
// It deliberately keeps the query scope explicit so callers cannot turn a
// management list into a tenant-wide database scan.
type ReadStore interface {
	ListTenants(context.Context, string, string) ([]Tenant, error)
	ListDepartments(context.Context, string, string, string) ([]Department, error)
	ListApplications(context.Context, string, string, string, string) ([]Application, error)
	ListPrincipals(context.Context, string, PrincipalType, string) ([]Principal, error)
	ListIdentityGrants(context.Context, string, string, string, string, PrincipalType, string, string, string) ([]Grant, error)
}

// OrganizationPageStore is the browser-facing bounded read port for the
// tenant tree. Internal bootstrap probes may continue using exact-ID reads.
// OrganizationPageStore 为浏览器组织管理提供有界分页读取；内部引导探针仍可按 ID 精确查询。
type OrganizationPageStore interface {
	PageTenants(context.Context, string, string, int, int) (OrganizationPage[Tenant], error)
	PageDepartments(context.Context, string, string, string, int, int) (OrganizationPage[Department], error)
	PageApplications(context.Context, string, string, string, string, int, int) (OrganizationPage[Application], error)
}

// ApplicationLifecycleStore exposes optimistic-concurrency protected
// deactivation without allowing hard deletion of referenced organization IDs.
// ApplicationLifecycleStore 提供 CAS 保护的停用，不硬删除仍可能被引用的组织 ID。
type ApplicationLifecycleStore interface {
	DisableApplication(context.Context, string, string, string, uint64) error
}

// GrantLifecycleStore is an optional write extension for adapters that support
// authorization revocation with an optimistic-concurrency fence.
type GrantLifecycleStore interface {
	RevokeGrant(context.Context, string, string, string, string, string, uint64) error
}

type SQLStore struct {
	administrativeRecorder         AdministrativeRecorder
	refreshSessionRecorder         RefreshSessionRecorder
	authorizationChangeRecorder    AuthorizationChangeRecorder
	permissionResourceResolver     AgentInstallationResolver
	capabilityResourceResolver     PermissionResourceResolver
	permissionTaskResolver         PermissionTaskResolver
	db                             *sql.DB
	permissionDecode               *permissionDecodeCache
	clock                          func() time.Time
	accessDecisionRecorder         AgentAccessDecisionRecorder
	principalLifecycleRecorder     PrincipalLifecycleRecorder
	credentialLifecycleRecorder    CredentialLifecycleRecorder
	enrollmentDecisionRecorder     EnrollmentDecisionRecorder
	enrollmentVerificationRecorder EnrollmentVerificationRecorder
	oidcBindingRecorder            OIDCBindingRecorder
}

func identityPersistenceError(operation string, err error) error {
	if sqlutil.IsUniqueViolation(err) {
		return fmt.Errorf("%s: %w", operation, ErrIdentityConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db, permissionDecode: newPermissionDecodeCache(), clock: func() time.Time { return time.Now().UTC() }}
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_authorization_version (
			scope_key VARCHAR(64) PRIMARY KEY, fingerprint VARCHAR(64) NOT NULL,
			epoch NUMERIC(20,0) CHECK (epoch>=0 AND epoch<=18446744073709551615) NOT NULL
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_identity_tenant (
			id VARCHAR(128) PRIMARY KEY, code VARCHAR(128) NOT NULL, name VARCHAR(255) NOT NULL,
			status VARCHAR(32) NOT NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, CONSTRAINT uq_identity_tenant_code UNIQUE (code)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_identity_department (
			id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, code VARCHAR(128) NOT NULL,
			name VARCHAR(255) NOT NULL, status VARCHAR(32) NOT NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, CONSTRAINT uq_identity_department_code UNIQUE (tenant_id,code));
CREATE INDEX IF NOT EXISTS idx_identity_department_tenant ON platform_identity_department (tenant_id);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_application (
			id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			code VARCHAR(128) NOT NULL, name VARCHAR(255) NOT NULL, status VARCHAR(32) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL, created_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_identity_application_code UNIQUE (tenant_id,department_id,code));
CREATE INDEX IF NOT EXISTS idx_identity_application_scope ON platform_identity_application (tenant_id,department_id);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_principal (
			id VARCHAR(128) NOT NULL, principal_type VARCHAR(32) NOT NULL, tenant_id VARCHAR(128) NOT NULL,
			roles_json TEXT NOT NULL, groups_json TEXT NOT NULL, active BOOLEAN NOT NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, PRIMARY KEY (principal_type,id));
CREATE INDEX IF NOT EXISTS idx_identity_principal_tenant ON platform_identity_principal (tenant_id);`,
		oidcBindingDDL,
		`CREATE TABLE IF NOT EXISTS platform_identity_grant (
			id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL, agent_instance_id VARCHAR(128) NOT NULL,
			subject_type VARCHAR(32) NOT NULL, subject_id VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL,
			effect VARCHAR(16) NOT NULL, status VARCHAR(32) NOT NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			grant_key_hash VARCHAR(64) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_identity_grant_key UNIQUE (grant_key_hash));
CREATE INDEX IF NOT EXISTS idx_identity_grant_lookup ON platform_identity_grant (tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_agent_access_request (
			id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL, agent_id VARCHAR(128) NOT NULL, agent_instance_id VARCHAR(128) NOT NULL,
			subject_type VARCHAR(32) NOT NULL, subject_id VARCHAR(128) NOT NULL, actions_json TEXT NOT NULL,
			reason VARCHAR(1000) NOT NULL, status VARCHAR(32) NOT NULL, reviewer_id VARCHAR(128) NOT NULL DEFAULT '',
			comment VARCHAR(1000) NOT NULL DEFAULT '', revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			pending_key_hash VARCHAR(64) NULL, created_at TIMESTAMPTZ(6) NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_identity_access_request_pending UNIQUE (pending_key_hash));
CREATE INDEX IF NOT EXISTS idx_identity_access_request_scope ON platform_identity_agent_access_request (tenant_id,department_id,application_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_identity_access_request_subject ON platform_identity_agent_access_request (tenant_id,subject_type,subject_id,status,created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_machine_credential (
			tenant_id VARCHAR(128) NOT NULL, principal_id VARCHAR(128) NOT NULL,
			secret_hash VARCHAR(64) NOT NULL, network_cidrs_json TEXT NOT NULL,
			status VARCHAR(24) NOT NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id,principal_id));
CREATE INDEX IF NOT EXISTS idx_machine_credential_status ON platform_identity_machine_credential (tenant_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_machine_access_token (
			token_hash VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, principal_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
			agent_instance_id VARCHAR(128) NOT NULL, actions_json TEXT NOT NULL, network_cidrs_json TEXT NOT NULL,
			credential_revision NUMERIC(20,0) CHECK (credential_revision>=0 AND credential_revision<=18446744073709551615) NOT NULL, expires_at TIMESTAMPTZ(6) NOT NULL, created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_machine_token_principal ON platform_identity_machine_access_token (tenant_id,principal_id,expires_at);
CREATE INDEX IF NOT EXISTS idx_machine_token_expiry ON platform_identity_machine_access_token (expires_at);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("identity schema: %w", err)
		}
	}
	if err := s.EnsureEnrollmentSchema(ctx); err != nil {
		return err
	}
	return s.EnsurePermissionSchema(ctx)
}

func (s *SQLStore) CreateMachineCredential(ctx context.Context, credential MachineCredential) error {
	if strings.TrimSpace(credential.TenantID) == "" || strings.TrimSpace(credential.PrincipalID) == "" || len(credential.SecretHash) != 64 {
		return ErrInvalidResource
	}
	cidrs, err := normalizeMachineCIDRs(credential.NetworkCIDRs)
	if err != nil {
		return err
	}
	var rolesJSON string
	var active bool
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT roles_json,active FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=?`), PrincipalServicePrincipal, credential.PrincipalID, credential.TenantID).Scan(&rolesJSON, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidPrincipal
	}
	if err != nil {
		return fmt.Errorf("validate machine principal for credential: %w", err)
	}
	if !active || len(unmarshalStrings(rolesJSON)) != 0 {
		return ErrInvalidPrincipal
	}
	now := s.clock().UTC()
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_machine_credential
		(tenant_id,principal_id,secret_hash,network_cidrs_json,status,revision,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?)`), credential.TenantID, credential.PrincipalID, credential.SecretHash,
		string(mustJSONStrings(cidrs)), "active", 1, now, now)
	if err != nil {
		return fmt.Errorf("create machine credential: %w", err)
	}
	return nil
}

func (s *SQLStore) GetMachineCredential(ctx context.Context, tenantID, principalID string) (MachineCredential, error) {
	var result MachineCredential
	var cidrsJSON string
	var reader interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	} = s.db
	if tx, joined, err := sqlutil.ContinuityTransaction(ctx, s.db); joined {
		if err != nil {
			return MachineCredential{}, err
		}
		if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			return MachineCredential{}, err
		}
		reader = tx
	}
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,principal_id,secret_hash,network_cidrs_json,status,revision,created_at,updated_at
		FROM platform_identity_machine_credential WHERE tenant_id=? AND principal_id=?`), tenantID, principalID).
		Scan(&result.TenantID, &result.PrincipalID, &result.SecretHash, &cidrsJSON, &result.Status, &result.Revision, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MachineCredential{}, ErrMachineCredentialNotFound
	}
	if err != nil {
		return MachineCredential{}, fmt.Errorf("get machine credential: %w", err)
	}
	if err := json.Unmarshal([]byte(cidrsJSON), &result.NetworkCIDRs); err != nil {
		return MachineCredential{}, fmt.Errorf("decode machine credential networks: %w", err)
	}
	if _, err := normalizeMachineCIDRs(result.NetworkCIDRs); err != nil {
		return MachineCredential{}, fmt.Errorf("validate stored machine credential networks: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ListMachineCredentials(ctx context.Context, tenantID string) ([]MachineCredential, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, ErrInvalidResource
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT tenant_id,principal_id,network_cidrs_json,status,revision,created_at,updated_at
		FROM platform_identity_machine_credential WHERE tenant_id=? ORDER BY principal_id LIMIT 100`), tenantID)
	if err != nil {
		return nil, fmt.Errorf("list machine credentials: %w", err)
	}
	defer rows.Close()
	result := make([]MachineCredential, 0)
	for rows.Next() {
		var item MachineCredential
		var cidrsJSON string
		if err := rows.Scan(&item.TenantID, &item.PrincipalID, &cidrsJSON, &item.Status, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan machine credential: %w", err)
		}
		if err := json.Unmarshal([]byte(cidrsJSON), &item.NetworkCIDRs); err != nil {
			return nil, fmt.Errorf("decode listed machine credential networks: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machine credentials: %w", err)
	}
	return result, nil
}

func (s *SQLStore) RotateMachineCredential(ctx context.Context, tenantID, principalID string, expected uint64, secretHash string, networks []string) (uint64, error) {
	if expected == 0 || len(secretHash) != 64 {
		return 0, ErrMachineCredentialConflict
	}
	cidrs, err := normalizeMachineCIDRs(networks)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential SET secret_hash=?,network_cidrs_json=?,revision=revision+1,updated_at=?
		WHERE tenant_id=? AND principal_id=? AND status='active' AND revision=?`), secretHash, string(mustJSONStrings(cidrs)), s.clock().UTC(), tenantID, principalID, expected)
	if err != nil {
		return 0, fmt.Errorf("rotate machine credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rotate machine credential rows: %w", err)
	}
	if rows != 1 {
		return 0, ErrMachineCredentialConflict
	}
	return expected + 1, nil
}

func (s *SQLStore) DisableMachineCredential(ctx context.Context, tenantID, principalID string, expected uint64) (uint64, error) {
	if expected == 0 {
		return 0, ErrMachineCredentialConflict
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential SET status='disabled',revision=revision+1,updated_at=?
		WHERE tenant_id=? AND principal_id=? AND status='active' AND revision=?`), s.clock().UTC(), tenantID, principalID, expected)
	if err != nil {
		return 0, fmt.Errorf("disable machine credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("disable machine credential rows: %w", err)
	}
	if rows != 1 {
		return 0, ErrMachineCredentialConflict
	}
	return expected + 1, nil
}

func (s *SQLStore) CreateMachineAccessToken(ctx context.Context, token MachineAccessToken) error {
	if len(token.TokenHash) != 64 || token.TenantID == "" || token.PrincipalID == "" || token.DepartmentID == "" || token.ApplicationID == "" || token.AgentInstanceID == "" || token.CredentialRevision == 0 || !token.ExpiresAt.After(s.clock()) {
		return ErrMachineCredentialsInvalid
	}
	actions, err := marshalMachineActions(token.Actions)
	if err != nil {
		return err
	}
	networks, err := json.Marshal(token.NetworkCIDRs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_machine_access_token
		(token_hash,tenant_id,principal_id,department_id,application_id,agent_instance_id,actions_json,network_cidrs_json,credential_revision,expires_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`), token.TokenHash, token.TenantID, token.PrincipalID, token.DepartmentID, token.ApplicationID,
		token.AgentInstanceID, actions, string(networks), token.CredentialRevision, token.ExpiresAt.UTC(), token.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("persist machine access token: %w", err)
	}
	return nil
}

func (s *SQLStore) GetMachineAccessToken(ctx context.Context, tokenHash string) (MachineAccessToken, error) {
	var result MachineAccessToken
	var actionsJSON, networksJSON string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT token_hash,tenant_id,principal_id,department_id,application_id,agent_instance_id,actions_json,network_cidrs_json,credential_revision,expires_at,created_at
		FROM platform_identity_machine_access_token WHERE token_hash=?`), tokenHash).
		Scan(&result.TokenHash, &result.TenantID, &result.PrincipalID, &result.DepartmentID, &result.ApplicationID, &result.AgentInstanceID,
			&actionsJSON, &networksJSON, &result.CredentialRevision, &result.ExpiresAt, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MachineAccessToken{}, ErrMachineCredentialsInvalid
	}
	if err != nil {
		return MachineAccessToken{}, fmt.Errorf("get machine access token: %w", err)
	}
	if err := json.Unmarshal([]byte(actionsJSON), &result.Actions); err != nil {
		return MachineAccessToken{}, fmt.Errorf("decode machine token actions: %w", err)
	}
	if err := json.Unmarshal([]byte(networksJSON), &result.NetworkCIDRs); err != nil {
		return MachineAccessToken{}, fmt.Errorf("decode machine token networks: %w", err)
	}
	return result, nil
}

func mustJSONStrings(values []string) []byte {
	raw, _ := json.Marshal(values)
	return raw
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLStore) CreateTenant(ctx context.Context, tenant Tenant) error {
	if err := tenant.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_tenant(id,code,name,status,revision,created_at) VALUES (?,?,?,?,?,?)`), tenant.ID, tenant.Code, tenant.Name, tenant.Status, tenant.Revision, s.clock())
	if err != nil {
		return identityPersistenceError("create identity tenant", err)
	}
	return nil
}

func (s *SQLStore) CreateDepartment(ctx context.Context, department Department) error {
	if err := department.Validate(); err != nil {
		return err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_tenant WHERE id=? AND status=?`), department.TenantID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("check identity tenant: %w", err)
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department(id,tenant_id,code,name,status,revision,created_at) VALUES (?,?,?,?,?,?,?)`), department.ID, department.TenantID, department.Code, department.Name, department.Status, department.Revision, s.clock())
	if err != nil {
		return identityPersistenceError("create identity department", err)
	}
	return nil
}

func (s *SQLStore) CreateApplication(ctx context.Context, application Application) error {
	if err := application.Validate(); err != nil {
		return err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_department WHERE id=? AND tenant_id=? AND status=?`), application.DepartmentID, application.TenantID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDepartmentNotFound
		}
		return fmt.Errorf("check identity department: %w", err)
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_application(id,tenant_id,department_id,code,name,status,revision,created_at) VALUES (?,?,?,?,?,?,?,?)`), application.ID, application.TenantID, application.DepartmentID, application.Code, application.Name, application.Status, application.Revision, s.clock())
	if err != nil {
		return identityPersistenceError("create identity application", err)
	}
	return nil
}

func normalizeOrganizationPage(page, pageSize int) (int, int, error) {
	if page < 1 || pageSize < 1 || pageSize > 100 {
		return 0, 0, ErrInvalidOrganizationPage
	}
	return page, pageSize, nil
}

func (s *SQLStore) PageTenants(ctx context.Context, tenantID, status string, page, pageSize int) (OrganizationPage[Tenant], error) {
	page, pageSize, err := normalizeOrganizationPage(page, pageSize)
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	if s == nil || s.db == nil || strings.TrimSpace(tenantID) == "" {
		return OrganizationPage[Tenant]{}, errors.New("identity database and tenant scope are required")
	}
	where, args := "id=?", []any{tenantID}
	if status != "" {
		where += " AND status=?"
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_tenant WHERE `+where), args...).Scan(&total); err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("count identity tenants: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,code,name,status,revision,created_at FROM platform_identity_tenant WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`), append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("page identity tenants: %w", err)
	}
	defer rows.Close()
	items := make([]Tenant, 0, pageSize)
	for rows.Next() {
		var value Tenant
		if err := rows.Scan(&value.ID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return OrganizationPage[Tenant]{}, fmt.Errorf("scan identity tenant: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("iterate identity tenants: %w", err)
	}
	return OrganizationPage[Tenant]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *SQLStore) PageDepartments(ctx context.Context, tenantID, departmentID, status string, page, pageSize int) (OrganizationPage[Department], error) {
	page, pageSize, err := normalizeOrganizationPage(page, pageSize)
	if err != nil {
		return OrganizationPage[Department]{}, err
	}
	if s == nil || s.db == nil || strings.TrimSpace(tenantID) == "" {
		return OrganizationPage[Department]{}, errors.New("identity database and tenant scope are required")
	}
	where, args := "tenant_id=?", []any{tenantID}
	if departmentID != "" {
		where += " AND id=?"
		args = append(args, departmentID)
	}
	if status != "" {
		where += " AND status=?"
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_department WHERE `+where), args...).Scan(&total); err != nil {
		return OrganizationPage[Department]{}, fmt.Errorf("count identity departments: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,code,name,status,revision,created_at FROM platform_identity_department WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`), append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return OrganizationPage[Department]{}, fmt.Errorf("page identity departments: %w", err)
	}
	defer rows.Close()
	items := make([]Department, 0, pageSize)
	for rows.Next() {
		var value Department
		if err := rows.Scan(&value.ID, &value.TenantID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return OrganizationPage[Department]{}, fmt.Errorf("scan identity department: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return OrganizationPage[Department]{}, fmt.Errorf("iterate identity departments: %w", err)
	}
	return OrganizationPage[Department]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *SQLStore) PageApplications(ctx context.Context, tenantID, departmentID, applicationID, status string, page, pageSize int) (OrganizationPage[Application], error) {
	page, pageSize, err := normalizeOrganizationPage(page, pageSize)
	if err != nil {
		return OrganizationPage[Application]{}, err
	}
	if s == nil || s.db == nil || strings.TrimSpace(tenantID) == "" {
		return OrganizationPage[Application]{}, errors.New("identity database and tenant scope are required")
	}
	where, args := "tenant_id=?", []any{tenantID}
	if departmentID != "" {
		where += " AND department_id=?"
		args = append(args, departmentID)
	}
	if applicationID != "" {
		where += " AND id=?"
		args = append(args, applicationID)
	}
	if status != "" {
		where += " AND status=?"
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_application WHERE `+where), args...).Scan(&total); err != nil {
		return OrganizationPage[Application]{}, fmt.Errorf("count identity applications: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,code,name,status,revision,created_at FROM platform_identity_application WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`), append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return OrganizationPage[Application]{}, fmt.Errorf("page identity applications: %w", err)
	}
	defer rows.Close()
	items := make([]Application, 0, pageSize)
	for rows.Next() {
		var value Application
		if err := rows.Scan(&value.ID, &value.TenantID, &value.DepartmentID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return OrganizationPage[Application]{}, fmt.Errorf("scan identity application: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return OrganizationPage[Application]{}, fmt.Errorf("iterate identity applications: %w", err)
	}
	return OrganizationPage[Application]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *SQLStore) DisableApplication(ctx context.Context, tenantID, departmentID, applicationID string, expectedRevision uint64) error {
	if s == nil || s.db == nil || tenantID == "" || departmentID == "" || applicationID == "" || expectedRevision == 0 {
		return ErrInvalidResource
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_application SET status='disabled',revision=revision+1 WHERE id=? AND tenant_id=? AND department_id=? AND status='active' AND revision=?`), applicationID, tenantID, departmentID, expectedRevision)
	if err != nil {
		return fmt.Errorf("disable identity application: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read disabled identity application result: %w", err)
	}
	if affected == 1 {
		return nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=?`), applicationID, tenantID, departmentID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrApplicationNotFound
		}
		return fmt.Errorf("check identity application after disable conflict: %w", err)
	}
	return ErrIdentityConflict
}

// ValidateApplicationScope is the identity Port consumed by Catalog when an
// installation is provisioned. It deliberately returns only a validation
// result; Catalog never receives or joins identity tables.
func (s *SQLStore) ValidateApplicationScope(ctx context.Context, tenantID, departmentID, applicationID string) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(departmentID) == "" || strings.TrimSpace(applicationID) == "" {
		return ErrApplicationNotFound
	}
	var exists int
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1
		FROM platform_identity_application
		WHERE id=? AND tenant_id=? AND department_id=? AND status=?`), applicationID, tenantID, departmentID, "active").Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrApplicationNotFound
	}
	if err != nil {
		return fmt.Errorf("validate identity application scope: %w", err)
	}
	return nil
}

func (s *SQLStore) CreatePrincipal(ctx context.Context, principal Principal) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_tenant WHERE id=? AND status=?`), principal.TenantID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("check identity principal tenant: %w", err)
	}
	roles, _ := marshalStrings(principal.Roles)
	groups, _ := marshalStrings(principal.Groups)
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES (?,?,?,?,?,?,?,?)`), principal.ID, principal.Type, principal.TenantID, roles, groups, principal.IsActive, 1, s.clock())
	if err != nil {
		return identityPersistenceError("create identity principal", err)
	}
	return nil
}

func (s *SQLStore) GetPrincipal(ctx context.Context, principalType PrincipalType, id string) (Principal, error) {
	var principal Principal
	var roles, groups string
	var active bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,principal_type,tenant_id,roles_json,groups_json,active,revision FROM platform_identity_principal WHERE principal_type=? AND id=?`), principalType, id).Scan(&principal.ID, &principal.Type, &principal.TenantID, &roles, &groups, &active, &principal.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrPrincipalNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("get identity principal: %w", err)
	}
	principal.IsActive = active
	principal.Roles = unmarshalStrings(roles)
	principal.Groups = unmarshalStrings(groups)
	var mode string
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type=? AND subject_id=?`), principalType, id).Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Principal{}, err
	}
	if mode == "v2" {
		// Unconverted consumers fail closed; scoped bindings are evaluated only
		// through the versioned permission port, never projected as global roles.
		principal.Roles = nil
		principal.Groups = nil
	} else if mode != "" && mode != "legacy" && mode != "shadow" {
		return Principal{}, ErrInvalidResource
	}
	return principal, nil
}

func (s *SQLStore) ListTenants(ctx context.Context, tenantID, status string) ([]Tenant, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	query := `SELECT id,code,name,status,revision,created_at FROM platform_identity_tenant WHERE id=?`
	args := []any{tenantID}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity tenants: %w", err)
	}
	defer rows.Close()
	result := make([]Tenant, 0)
	for rows.Next() {
		var value Tenant
		if err := rows.Scan(&value.ID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity tenant: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity tenants: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ListDepartments(ctx context.Context, tenantID, departmentID, status string) ([]Department, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	query := `SELECT id,tenant_id,code,name,status,revision,created_at FROM platform_identity_department WHERE tenant_id=?`
	args := []any{tenantID}
	if departmentID != "" {
		query += ` AND id=?`
		args = append(args, departmentID)
	}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity departments: %w", err)
	}
	defer rows.Close()
	result := make([]Department, 0)
	for rows.Next() {
		var value Department
		if err := rows.Scan(&value.ID, &value.TenantID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity department: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity departments: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ListApplications(ctx context.Context, tenantID, departmentID, applicationID, status string) ([]Application, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	query := `SELECT id,tenant_id,department_id,code,name,status,revision,created_at FROM platform_identity_application WHERE tenant_id=? AND department_id=?`
	args := []any{tenantID, departmentID}
	if applicationID != "" {
		query += ` AND id=?`
		args = append(args, applicationID)
	}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity applications: %w", err)
	}
	defer rows.Close()
	result := make([]Application, 0)
	for rows.Next() {
		var value Application
		if err := rows.Scan(&value.ID, &value.TenantID, &value.DepartmentID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity application: %w", err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity applications: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ListPrincipals(ctx context.Context, tenantID string, principalType PrincipalType, id string) ([]Principal, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	query := `SELECT id,principal_type,tenant_id,roles_json,groups_json,active,revision FROM platform_identity_principal WHERE tenant_id=?`
	args := []any{tenantID}
	if principalType != "" {
		query += ` AND principal_type=?`
		args = append(args, principalType)
	}
	if id != "" {
		query += ` AND id=?`
		args = append(args, id)
	}
	query += ` ORDER BY principal_type,id`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity principals: %w", err)
	}
	defer rows.Close()
	result := make([]Principal, 0)
	for rows.Next() {
		var value Principal
		var roles, groups string
		if err := rows.Scan(&value.ID, &value.Type, &value.TenantID, &roles, &groups, &value.IsActive, &value.Revision); err != nil {
			return nil, fmt.Errorf("scan identity principal: %w", err)
		}
		value.Roles = unmarshalStrings(roles)
		value.Groups = unmarshalStrings(groups)
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity principals: %w", err)
	}
	return result, nil
}

func (s *SQLStore) CreateGrant(ctx context.Context, grant Grant) error {
	if err := grant.Validate(); err != nil {
		return err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=? AND status=?`), grant.ApplicationID, grant.TenantID, grant.DepartmentID, "active").Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrApplicationNotFound
		}
		return fmt.Errorf("check identity application: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? AND active=?`), grant.SubjectType, grant.SubjectID, grant.TenantID, true).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPrincipalNotFound
		}
		return fmt.Errorf("check identity grant principal: %w", err)
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`), grant.ID, grant.TenantID, grant.DepartmentID, grant.ApplicationID, grant.AgentInstanceID, grant.SubjectType, grant.SubjectID, grant.Action, grant.Effect, grant.Status, grant.Revision, grantKeyHash(grant), s.clock())
	if err != nil {
		return identityPersistenceError("create identity grant", err)
	}
	return nil
}

// RevokeGrant is deliberately scoped by all four resource coordinates. A
// caller cannot revoke a grant from another application by knowing only its
// opaque ID, and a stale revision is rejected instead of silently succeeding.
func (s *SQLStore) RevokeGrant(ctx context.Context, tenantID, departmentID, applicationID, agentInstanceID, id string, expectedRevision uint64) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(departmentID) == "" || strings.TrimSpace(applicationID) == "" || strings.TrimSpace(agentInstanceID) == "" || strings.TrimSpace(id) == "" || expectedRevision == 0 {
		return ErrIdentityConflict
	}
	var status string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_identity_grant
		WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND id=?`), tenantID, departmentID, applicationID, agentInstanceID, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrGrantNotFound
	}
	if err != nil {
		return fmt.Errorf("check identity grant for revoke: %w", err)
	}
	if status != GrantActive {
		return ErrIdentityConflict
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_grant
		SET status=?, revision=revision+1 WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND id=? AND status=? AND revision=?`), GrantRevoked, tenantID, departmentID, applicationID, agentInstanceID, id, GrantActive, expectedRevision)
	if err != nil {
		return fmt.Errorf("revoke identity grant: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke identity grant rows: %w", err)
	}
	if rows != 1 {
		return ErrIdentityConflict
	}
	return nil
}

func grantKeyHash(grant Grant) string {
	// A bounded digest keeps scope/idempotency indexes compact while retaining
	// every identity dimension in the canonical input.
	key := strings.Join([]string{grant.TenantID, grant.DepartmentID, grant.ApplicationID, grant.AgentInstanceID, string(grant.SubjectType), grant.SubjectID, grant.Action, grant.Effect}, "\x00")
	if grant.ResourceType != "" {
		data := grant.DataScope
		data.IDs = append([]string(nil), data.IDs...)
		sort.Strings(data.IDs)
		raw, _ := json.Marshal([]any{grant.ResourceType, grant.ResourceID, data, grant.SourceID})
		key += "\x00" + string(raw)
	}
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:])
}

func (s *SQLStore) ListGrants(ctx context.Context, tenantID, departmentID, applicationID, agentInstanceID string, subjectType PrincipalType, subjectID, action string) ([]Grant, error) {
	return s.ListIdentityGrants(ctx, tenantID, departmentID, applicationID, agentInstanceID, subjectType, subjectID, action, "")
}

func (s *SQLStore) ListIdentityGrants(ctx context.Context, tenantID, departmentID, applicationID, agentInstanceID string, subjectType PrincipalType, subjectID, action, status string) ([]Grant, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("identity database is required")
	}
	query := `SELECT id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision FROM platform_identity_grant WHERE tenant_id=? AND department_id=? AND application_id=?`
	args := []any{tenantID, departmentID, applicationID}
	if agentInstanceID != "" {
		query += ` AND agent_instance_id=?`
		args = append(args, agentInstanceID)
	}
	if subjectType != "" {
		query += ` AND subject_type=?`
		args = append(args, subjectType)
	}
	if subjectID != "" {
		query += ` AND subject_id=?`
		args = append(args, subjectID)
	}
	if action != "" {
		query += ` AND action=?`
		args = append(args, action)
	}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity grants: %w", err)
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var grant Grant
		if err := rows.Scan(&grant.ID, &grant.TenantID, &grant.DepartmentID, &grant.ApplicationID, &grant.AgentInstanceID, &grant.SubjectType, &grant.SubjectID, &grant.Action, &grant.Effect, &grant.Status, &grant.Revision); err != nil {
			return nil, fmt.Errorf("scan identity grant: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity grants: %w", err)
	}
	return grants, nil
}

func marshalStrings(values []string) (string, error) {
	raw, err := json.Marshal(values)
	return string(raw), err
}

func unmarshalStrings(raw string) []string {
	var values []string
	if json.Unmarshal([]byte(raw), &values) != nil {
		return nil
	}
	return values
}

var _ Store = (*SQLStore)(nil)

func pageCompanyDirectory(ctx context.Context, reader permissionReader, tenantID, status string, page, pageSize int) (OrganizationPage[Tenant], error) {
	page, pageSize, err := normalizeOrganizationPage(page, pageSize)
	if err != nil {
		return OrganizationPage[Tenant]{}, err
	}
	where, args := "1=1", []any{}
	if tenantID != "" {
		where, args = "id=?", []any{tenantID}
	}
	if status != "" {
		where += " AND status=?"
		args = append(args, status)
	}
	var total int64
	if err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_tenant WHERE `+where), args...).Scan(&total); err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("count identity tenants: %w", err)
	}
	rows, err := reader.QueryContext(ctx, sqlutil.Bind(`SELECT id,code,name,status,revision,created_at FROM platform_identity_tenant WHERE `+where+` ORDER BY id LIMIT ? OFFSET ?`), append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("page identity tenants: %w", err)
	}
	defer rows.Close()
	items := make([]Tenant, 0, pageSize)
	for rows.Next() {
		var value Tenant
		if err := rows.Scan(&value.ID, &value.Code, &value.Name, &value.Status, &value.Revision, &value.CreatedAt); err != nil {
			return OrganizationPage[Tenant]{}, fmt.Errorf("scan identity tenant: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return OrganizationPage[Tenant]{}, fmt.Errorf("iterate identity tenants: %w", err)
	}
	return OrganizationPage[Tenant]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}
