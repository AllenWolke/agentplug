package identity

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type DepartmentAgentPolicyState struct {
	Managed   bool                  `json:"managed"`
	CanManage bool                  `json:"can_manage"`
	Policy    DepartmentAgentPolicy `json:"policy"`
}

func (s *SQLStore) DepartmentAgentPolicy(ctx context.Context, actor sharedkernel.Scope, tenant, department string) (DepartmentAgentPolicyState, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || !validPermissionResourceID(tenant) || !validPermissionResourceID(department) {
		return DepartmentAgentPolicyState{}, ErrPermissionDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DepartmentAgentPolicyState{}, err
	}
	defer tx.Rollback()
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DepartmentAgentPolicyState{}, err
	}
	if owner.Principal.TenantID != actor.TenantID {
		return DepartmentAgentPolicyState{}, ErrPermissionDenied
	}
	now := s.clock().UTC()
	canManage := authorizeDepartmentAgentPolicy(owner, actor, tenant, department, now) == nil
	scope := ManagementScope{Type: "department", TenantID: tenant, DepartmentID: department}
	if !canManage {
		decision, err := EvaluatePermission(owner, PermissionQuery{Action: "authorization.read", Scope: scope, Now: now})
		if err != nil || !decision.Allowed {
			return DepartmentAgentPolicyState{}, ErrPermissionDenied
		}
	}
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return DepartmentAgentPolicyState{}, err
	}
	policy, managed, err := readDepartmentAgentPolicy(ctx, tx, tenant, department)
	if err != nil {
		return DepartmentAgentPolicyState{}, err
	}
	return DepartmentAgentPolicyState{Managed: managed, CanManage: canManage, Policy: policy}, tx.Commit()
}

// An uncertain submit is recovered with the original idempotency key, not a
// new command or another proof. This query never executes the command again.
func (s *SQLStore) DepartmentAgentChangeReceipt(ctx context.Context, actor sharedkernel.Scope, idempotencyKey string) (DepartmentAgentChangeReceipt, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || !validPermissionResourceID(idempotencyKey) {
		return DepartmentAgentChangeReceipt{}, ErrPermissionDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	defer tx.Rollback()
	key := permissionHash([]byte("department-agent-change\x00" + actor.PrincipalID + "\x00" + idempotencyKey))
	var raw []byte
	var tenant, department string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,receipt_json FROM platform_identity_department_agent_change WHERE idempotency_key=? AND actor_id=?`), key, actor.PrincipalID).Scan(&tenant, &department, &raw); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	if err := authorizeDepartmentAgentPolicy(owner, actor, tenant, department, s.clock().UTC()); err != nil {
		return DepartmentAgentChangeReceipt{}, err
	}
	var receipt DepartmentAgentChangeReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit()
}
