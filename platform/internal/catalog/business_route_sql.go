package catalog

import (
	"context"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Bounded exact-scope Catalog projection. The composition must intersect
// current caller/parent-machine permissions before returning any route plan.
func (s *SQLStore) ListRouteInstallations(ctx context.Context, scope sharedkernel.Scope, allowedAgents []string) ([]Installation, error) {
	if scope.ValidateTrusted() != nil || len(allowedAgents) < 1 || len(allowedAgents) > 32 {
		return nil, ErrBusinessRouteUnavailable
	}
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	placeholders := []string{}
	seen := map[string]bool{}
	for _, id := range allowedAgents {
		if !routeIdentifier(id) || seen[id] {
			return nil, ErrBusinessRouteUnavailable
		}
		seen[id] = true
		args = append(args, id)
		placeholders = append(placeholders, "?")
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,version_id,status,revision FROM platform_catalog_installation WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id IN (`+strings.Join(placeholders, ",")+`) AND status='active' ORDER BY id ASC LIMIT 129`), args...)
	if err != nil {
		return nil, ErrBusinessRouteUnavailable
	}
	defer rows.Close()
	result := []Installation{}
	for rows.Next() {
		var value Installation
		if rows.Scan(&value.ID, &value.TenantID, &value.DepartmentID, &value.ApplicationID, &value.AgentID, &value.VersionID, &value.Status, &value.Revision) != nil {
			return nil, ErrBusinessRouteUnavailable
		}
		result = append(result, value)
		if len(result) > 128 {
			return nil, ErrBusinessRouteUnavailable
		}
	}
	if rows.Err() != nil {
		return nil, ErrBusinessRouteUnavailable
	}
	return result, nil
}
