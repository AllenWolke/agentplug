package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrFirstAdministratorUnavailable = errors.New("first administrator requires an empty identity store, current schema and atomic audit recorder")

// FirstAdministratorRequest 仅用于部署维护入口，不是浏览器或长期运行配置。
type FirstAdministratorRequest struct {
	TenantID          string `json:"tenant_id"`
	TenantName        string `json:"tenant_name"`
	DepartmentID      string `json:"department_id"`
	DepartmentName    string `json:"department_name"`
	ApplicationID     string `json:"application_id"`
	ApplicationName   string `json:"application_name"`
	PrincipalID       string `json:"principal_id"`
	OperatorID        string `json:"operator_id"`
	Issuer            string `json:"oidc_issuer"`
	Subject           string `json:"oidc_subject"`
	LocalPassword     string `json:"local_password,omitempty"`
	ApprovalReference string `json:"approval_reference"`
}

var initialIdentityID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (r FirstAdministratorRequest) Validate() error {
	for _, id := range []string{r.TenantID, r.DepartmentID, r.ApplicationID, r.PrincipalID, r.OperatorID, r.ApprovalReference} {
		if !initialIdentityID.MatchString(id) || strings.HasPrefix(strings.ToLower(id), "replace") {
			return ErrInvalidResource
		}
	}
	for _, name := range []string{r.TenantName, r.DepartmentName, r.ApplicationName} {
		if strings.TrimSpace(name) == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 255 || strings.ContainsAny(name, "\x00\r\n") {
			return ErrInvalidResource
		}
	}
	if r.LocalPassword != "" {
		if len(r.LocalPassword) < 10 || len(r.LocalPassword) > 128 || r.Issuer != "" || r.Subject != "" {
			return ErrInvalidResource
		}
		return nil
	}
	if !validOIDCIdentity(r.Issuer, r.Subject) || strings.Contains(r.Issuer, ".invalid") || strings.Contains(r.Issuer, "example.com") || strings.HasPrefix(strings.ToLower(r.Subject), "replace") {
		return ErrInvalidResource
	}
	return nil
}

type FirstAdministratorRecorder func(context.Context, *sql.Tx, FirstAdministratorRequest, time.Time) error

// FirstAdministratorVerifier 由组合根注入 Schema/权限只读检查，不导入其实现。
type FirstAdministratorVerifier func(context.Context, *sql.DB) error

// InitializeFirstAdministrator 将组织、管理员及绑定原子创建；已有任何 IAM 数据均拒绝。
// 审计和 Outbox 由调用方通过事务 Port 写入；本方法不建表、不恢复撤销的角色。
func (s *SQLStore) InitializeFirstAdministrator(ctx context.Context, request FirstAdministratorRequest, verify FirstAdministratorVerifier, record FirstAdministratorRecorder) (result error) {
	if s == nil || s.db == nil || verify == nil || record == nil {
		return ErrFirstAdministratorUnavailable
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if err := verify(ctx, s.db); err != nil {
		return err
	}
	local := request.LocalPassword != ""
	var passwordHash string
	if local {
		var err error
		passwordHash, err = hashEnrollmentPassword(request.LocalPassword)
		if err != nil {
			return err
		}
		// Plaintext never reaches the audit/Outbox recorder.
		request.LocalPassword = ""
	}
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	var database string
	if err := connection.QueryRowContext(ctx, sqlutil.Bind("SELECT current_database()")).Scan(&database); err != nil {
		return err
	}
	lockHash := sha256.Sum256([]byte("first-admin:" + database))
	lock := int64(binary.BigEndian.Uint64(lockHash[:8]))
	var acquired bool
	if err := connection.QueryRowContext(ctx, sqlutil.Bind("SELECT pg_try_advisory_lock(?)"), lock).Scan(&acquired); err != nil || !acquired {
		return ErrFirstAdministratorUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var released bool
		if err := connection.QueryRowContext(cleanup, sqlutil.Bind("SELECT pg_advisory_unlock(?)"), lock).Scan(&released); err != nil || !released {
			// 释放失败时丢弃物理连接，不能把仍持有命名锁的连接退回池中。
			_ = connection.Raw(func(any) error { return driver.ErrBadConn })
			if result == nil {
				result = ErrFirstAdministratorUnavailable
			}
		}
	}()
	rows, err := connection.QueryContext(ctx, sqlutil.Bind(`SELECT c.relname,'PostgreSQL',CASE WHEN c.relkind IN ('r','p') THEN 'BASE TABLE' ELSE 'VIEW' END FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v','m','f') ORDER BY c.relname`))
	if err != nil {
		return err
	}
	required := map[string]bool{"platform_identity_tenant": false, "platform_identity_department": false,
		"platform_identity_application": false, "platform_identity_principal": false,
		"platform_identity_oidc_binding": false, "platform_audit_event": false, "platform_notification_outbox": false}
	var tables []string
	// 只读登记过的 IAM 表；未来未知表不能通过前缀隐式获得访问权限。
	identityTables := map[string]bool{
		"platform_identity_permission_request": true,
		"platform_identity_tenant":             true, "platform_identity_department": true,
		"platform_identity_application": true, "platform_identity_principal": true,
		"platform_identity_oidc_binding": true, "platform_identity_grant": true,
		"platform_identity_enrollment": true, "platform_identity_local_credential": true,
		"platform_identity_registration_rate_limit": true, "platform_identity_authorization_version": true,
		"platform_identity_agent_access_request": true, "platform_identity_machine_credential": true,
		"platform_identity_machine_access_token": true,
		"platform_identity_role_definition":      true, "platform_identity_preset_definition": true,
		"platform_identity_membership": true, "platform_identity_role_binding": true,
		"platform_identity_delegation": true, "platform_identity_authorization_change": true,
		"platform_identity_policy_migration": true, "platform_identity_continuity_guard": true,
		"platform_identity_refresh_family": true, "platform_identity_refresh_token": true,
		"platform_identity_refresh_oidc_binding":    true,
		"platform_identity_step_up":                 true,
		"platform_identity_oidc_step_up_challenge":  true,
		"platform_identity_oidc_step_up_proof":      true,
		"platform_identity_task_assignment":         true,
		"platform_identity_workload_binding":        true,
		"platform_identity_department_agent_policy": true,
		"platform_identity_department_agent_entry":  true,
		"platform_identity_department_agent_change": true,
		"platform_identity_permission_batch":        true,
	}
	for rows.Next() {
		var name, kind string
		var engine sql.NullString
		if err := rows.Scan(&name, &engine, &kind); err != nil {
			rows.Close()
			return err
		}
		_, mandatory := required[name]
		if mandatory || strings.HasPrefix(name, "platform_identity_") {
			if strings.HasPrefix(name, "platform_identity_") && !identityTables[name] {
				rows.Close()
				return ErrFirstAdministratorUnavailable
			}
			if !initialIdentityID.MatchString(name) || engine.String != "PostgreSQL" || kind != "BASE TABLE" {
				rows.Close()
				return ErrFirstAdministratorUnavailable
			}
			if mandatory {
				required[name] = true
			}
			// Immutable directory definitions and the continuity mutex are seeded
			// by schema migration; they are not existing authenticated identities.
			if strings.HasPrefix(name, "platform_identity_") && name != "platform_identity_role_definition" && name != "platform_identity_preset_definition" && name != "platform_identity_continuity_guard" {
				tables = append(tables, name)
			}
		}
	}
	readError := rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readError != nil {
		return readError
	}
	for _, present := range required {
		if !present {
			return ErrFirstAdministratorUnavailable
		}
	}
	tx, err := connection.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range tables {
		var exists int
		err := tx.QueryRowContext(ctx, sqlutil.Bind("SELECT 1 FROM \""+table+"\" LIMIT 1 FOR UPDATE")).Scan(&exists)
		if err == nil {
			return ErrFirstAdministratorUnavailable
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	now := s.clock().UTC()
	statements := []struct {
		query  string
		values []any
	}{
		{"INSERT INTO platform_identity_tenant(id,code,name,status,revision,created_at) VALUES (?,?,?,'active',1,?)", []any{request.TenantID, request.TenantID, request.TenantName, now}},
		{"INSERT INTO platform_identity_department(id,tenant_id,code,name,status,revision,created_at) VALUES (?,?,?,?,'active',1,?)", []any{request.DepartmentID, request.TenantID, request.DepartmentID, request.DepartmentName, now}},
		{"INSERT INTO platform_identity_application(id,tenant_id,department_id,code,name,status,revision,created_at) VALUES (?,?,?,?,?,'active',1,?)", []any{request.ApplicationID, request.TenantID, request.DepartmentID, request.ApplicationID, request.ApplicationName, now}},
		{"INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES (?,'user',?,'[]','[]',TRUE,1,?)", []any{request.PrincipalID, request.TenantID, now}},
	}
	if local {
		statements = append(statements, struct {
			query  string
			values []any
		}{`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,TRUE,?,?)`, []any{request.PrincipalID, request.TenantID, request.DepartmentID, request.ApplicationID, request.PrincipalID, passwordHash, now, now}})
	} else {
		statements = append(statements, struct {
			query  string
			values []any
		}{"INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,created_at,revision,updated_at) VALUES (?,?,?,?,?,?,?,'active',?,1,?)", []any{oidcIdentityKey(request.Issuer, request.Subject), request.Issuer, request.Subject, request.PrincipalID, request.TenantID, request.DepartmentID, request.ApplicationID, now, now}})
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(statement.query), statement.values...); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch,batch_id) VALUES('user',?,'v2',1,1,?)`), request.PrincipalID, "first-admin:"+request.ApprovalReference); err != nil {
		return err
	}
	scope := ManagementScope{Type: "application", TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID}
	key := permissionHash([]byte(request.TenantID + "\x00" + request.PrincipalID + "\x00" + request.ApprovalReference))
	member := Membership{ID: "first-member-" + key, SubjectID: request.PrincipalID, Scope: scope, Status: "active", Revision: 1}
	raw, err := json.Marshal(member)
	if err != nil {
		return err
	}
	memberKey, _ := json.Marshal([]any{member.SubjectID, member.Scope})
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, member.SubjectID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), permissionHash(memberKey)); err != nil {
		return err
	}
	if err := insertRoleBinding(ctx, tx, RoleBinding{ID: "first-super-" + key, SubjectID: request.PrincipalID, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "bootstrap:" + request.ApprovalReference}); err != nil {
		return err
	}
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, request.PrincipalID)
	if err != nil {
		return err
	}
	if err := requireSuperAdministrator(snapshot, "administrator.appoint", now); err != nil {
		return err
	}
	if err := ensurePermanentAdministrator(ctx, tx, "", "", now); err != nil {
		return err
	}
	if err := record(ctx, tx, request, now); err != nil {
		return err
	}
	return tx.Commit()
}
