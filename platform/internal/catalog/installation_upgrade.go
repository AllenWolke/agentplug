package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/sqlutil"
)

// InstallationUpgradeStore changes the selected immutable release while the
// instance cannot accept execution. A fresh deployment observation is required.
type InstallationUpgradeStore interface {
	UpgradeInstallation(context.Context, string, string, uint64) error
}

func (s *SQLStore) UpgradeInstallation(ctx context.Context, id, versionID string, expectedRevision uint64) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(versionID) == "" || expectedRevision == 0 {
		return ErrRevisionConflict
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_installation AS i
  SET version_id=?,status=?,revision=revision+1,updated_at=?
  WHERE i.id=? AND i.revision=? AND i.status IN (?,?) AND i.version_id<>?
  AND EXISTS (SELECT 1 FROM platform_catalog_installation_options o WHERE o.installation_id=i.id)
  AND EXISTS (SELECT 1 FROM platform_catalog_version v
    JOIN platform_catalog_version_artifact va ON va.version_id=v.id
    JOIN platform_catalog_definition d ON d.id=v.definition_id
    JOIN platform_catalog_definition_metadata dm ON dm.definition_id=d.id
    WHERE v.id=? AND v.status=? AND d.status=? AND d.agent_key=i.agent_id)`),
		versionID, InstallationProvisioning, s.clock(), id, expectedRevision, InstallationProvisioning, InstallationSuspended,
		versionID, versionID, DefinitionPublished, DefinitionPublished)
	if err != nil {
		return fmt.Errorf("upgrade catalog installation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrRevisionConflict
	}
	return nil
}
