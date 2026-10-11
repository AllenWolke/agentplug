package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type PermissionMachineDirectory interface {
	PagePermissionMachines(context.Context, sharedkernel.Scope, string, int, int) (OrganizationPage[Principal], error)
}

// Human and machine directories are separate projections. The machine list
// contains no credentials or cached roles, and uses the same all-binding
// management boundary as credential lifecycle operations.
func (s *SQLStore) PagePermissionMachines(ctx context.Context, actor sharedkernel.Scope, id string, page, size int) (OrganizationPage[Principal], error) {
	result := OrganizationPage[Principal]{Items: []Principal{}, Page: page, PageSize: size}
	if actor.Validate() != nil || actor.PrincipalType != "user" || len(id) > 128 || page < 1 || page > 100000 || size < 1 || size > 100 {
		return result, ErrInvalidResource
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return result, err
	}
	if owner.Mode != "v2" || !owner.Principal.IsActive || owner.Principal.TenantID != actor.TenantID {
		return result, ErrPermissionDenied
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,principal_type,tenant_id,active,revision FROM platform_identity_principal WHERE principal_type='service_principal' AND tenant_id=? AND (?='' OR id=?) ORDER BY id LIMIT 1001`), actor.TenantID, id, id)
	if err != nil {
		return result, err
	}
	var candidates []Principal
	for rows.Next() {
		var p Principal
		if err := rows.Scan(&p.ID, &p.Type, &p.TenantID, &p.IsActive, &p.Revision); err != nil {
			rows.Close()
			return result, err
		}
		candidates = append(candidates, p)
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return result, rowErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if len(candidates) > 1000 {
		return result, ErrInvalidResource
	}
	allowed := []Principal{}
	for _, candidate := range candidates {
		err := authorizeWorkloadCredential(ctx, tx, owner, actor.TenantID, candidate.ID, PermissionQuery{Now: s.clock().UTC()})
		if errors.Is(err, ErrPermissionDenied) {
			continue
		}
		if err != nil {
			return result, err
		}
		allowed = append(allowed, candidate)
	}
	result.Total = int64(len(allowed))
	start := (page - 1) * size
	if start < len(allowed) {
		end := start + size
		if end > len(allowed) {
			end = len(allowed)
		}
		result.Items = allowed[start:end]
	}
	return result, tx.Commit()
}
