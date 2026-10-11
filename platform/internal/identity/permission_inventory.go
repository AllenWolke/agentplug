package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

type PermissionInventoryItem struct {
	Principal             Principal `json:"principal"`
	LocalCredentialActive bool      `json:"local_credential_active"`
	ActiveOIDCBindings    int       `json:"active_oidc_bindings"`
	Grants                []Grant   `json:"grants"`
}

type PermissionInventory struct {
	ReadAt       time.Time                 `json:"read_at"`
	Items        []PermissionInventoryItem `json:"items"`
	SourceDigest string                    `json:"source_digest"`
}

// InspectPermissionInventory is compatible with the predecessor schema and
// issues SELECT only. Password hashes, bearer credentials and OIDC subjects
// are deliberately absent from the inventory projection and its digest.
func (s *SQLStore) InspectPermissionInventory(ctx context.Context) (PermissionInventory, error) {
	if s == nil || s.db == nil {
		return PermissionInventory{}, errors.New("identity database is required")
	}
	result := PermissionInventory{ReadAt: s.clock().UTC(), Items: []PermissionInventoryItem{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT p.id,p.principal_type,p.tenant_id,p.roles_json,p.groups_json,p.active,p.revision,
		EXISTS(SELECT 1 FROM platform_identity_local_credential c WHERE c.principal_id=p.id AND c.tenant_id=p.tenant_id AND c.active=TRUE),
		(SELECT COUNT(*) FROM platform_identity_oidc_binding o WHERE o.principal_id=p.id AND o.tenant_id=p.tenant_id AND o.status='active')
		FROM platform_identity_principal p ORDER BY p.principal_type,p.id`))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item PermissionInventoryItem
		var roles, groups string
		item.Grants = []Grant{}
		if err := rows.Scan(&item.Principal.ID, &item.Principal.Type, &item.Principal.TenantID, &roles, &groups, &item.Principal.IsActive, &item.Principal.Revision, &item.LocalCredentialActive, &item.ActiveOIDCBindings); err != nil {
			rows.Close()
			return result, err
		}
		if err := json.Unmarshal([]byte(roles), &item.Principal.Roles); err != nil {
			rows.Close()
			return result, err
		}
		if err := json.Unmarshal([]byte(groups), &item.Principal.Groups); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return result, err
	}
	if closeErr != nil {
		return result, closeErr
	}
	grants, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision FROM platform_identity_grant ORDER BY subject_type,subject_id,id`))
	if err != nil {
		return result, err
	}
	index := map[string]int{}
	for i, item := range result.Items {
		index[string(item.Principal.Type)+"\x00"+item.Principal.ID] = i
	}
	for grants.Next() {
		var g Grant
		if err := grants.Scan(&g.ID, &g.TenantID, &g.DepartmentID, &g.ApplicationID, &g.AgentInstanceID, &g.SubjectType, &g.SubjectID, &g.Action, &g.Effect, &g.Status, &g.Revision); err != nil {
			grants.Close()
			return result, err
		}
		if i, ok := index[string(g.SubjectType)+"\x00"+g.SubjectID]; ok {
			result.Items[i].Grants = append(result.Items[i].Grants, g)
		}
	}
	err = grants.Err()
	closeErr = grants.Close()
	if err != nil {
		return result, err
	}
	if closeErr != nil {
		return result, closeErr
	}
	raw, err := json.Marshal(result.Items)
	if err != nil {
		return result, err
	}
	result.SourceDigest = permissionHash(raw)
	return result, tx.Commit()
}
