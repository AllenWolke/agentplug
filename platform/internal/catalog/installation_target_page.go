package catalog

import (
	"context"
	"strings"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Permission pickers use stable keyset pages, so an installation beyond the
// first 100 records remains selectable without widening the authorized scope.
type InstallationTargetPageReader interface {
	PageInstallationTargets(context.Context, string, string, string, string, int) ([]Installation, string, error)
}

func (s *SQLStore) PageInstallationTargets(ctx context.Context, tenant, department, application, after string, limit int) ([]Installation, string, error) {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(department) == "" || strings.TrimSpace(application) == "" || len(after) > 128 || limit < 1 || limit > 100 {
		return nil, "", ErrInvalidInstallation
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT i.id,i.tenant_id,i.department_id,i.application_id,i.agent_id,i.version_id,o.display_name,i.status FROM platform_catalog_installation i JOIN platform_catalog_installation_options o ON o.installation_id=i.id WHERE i.tenant_id=? AND i.department_id=? AND i.application_id=? AND i.id>? ORDER BY i.id LIMIT ?`), tenant, department, application, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Installation, 0, limit+1)
	for rows.Next() {
		var item Installation
		if err := rows.Scan(&item.ID, &item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.AgentID, &item.VersionID, &item.DisplayName, &item.Status); err != nil {
			return nil, "", err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(items) > limit {
		return items[:limit], items[limit-1].ID, nil
	}
	return items, "", nil
}
