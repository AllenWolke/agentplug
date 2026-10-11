package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
)

type DepartmentAdministrationCreationRepository interface {
	CreateDepartmentWithAdministrationContext(context.Context, Department) error
}

// The application here is an internal session and policy container, not an
// Agent application. Creating it with the department makes member management
// usable before any Agent is installed. Both records commit or roll back.
func (s *SQLStore) CreateDepartmentWithAdministrationContext(ctx context.Context, department Department) error {
	if s == nil || s.db == nil || ctx == nil || department.Status != "active" {
		return ErrInvalidResource
	}
	if err := department.Validate(); err != nil {
		return err
	}
	application := Application{ID: "department-home-" + permissionHash([]byte(department.ID)), TenantID: department.TenantID, DepartmentID: department.ID, Code: "department-home", Name: department.Name, Status: "active", Revision: 1}
	if err := application.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_tenant WHERE id=? AND status='active' FOR SHARE`), department.TenantID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTenantNotFound
		}
		return err
	}
	now := s.clock().UTC()
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department(id,tenant_id,code,name,status,revision,created_at) VALUES(?,?,?,?,?,?,?)`), department.ID, department.TenantID, department.Code, department.Name, department.Status, department.Revision, now); err != nil {
		return identityPersistenceError("create company department", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_application(id,tenant_id,department_id,code,name,status,revision,created_at) VALUES(?,?,?,?,?,?,?,?)`), application.ID, application.TenantID, application.DepartmentID, application.Code, application.Name, application.Status, application.Revision, now); err != nil {
		return identityPersistenceError("create department administration context", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_department_agent_policy(tenant_id,department_id,revision,entries_digest,updated_by,updated_at) VALUES(?,?,1,?,'department-creation',?)`), department.TenantID, department.ID, departmentAgentEntriesDigest(nil), now); err != nil {
		return identityPersistenceError("create empty department Agent ceiling", err)
	}
	return tx.Commit()
}
