package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Human authentication is independent of business roles. Migrated principals
// never receive a legacy role array as an authorization fallback.
func authenticationRoleProjection(ctx context.Context, reader permissionReader, subject, encoded string) ([]string, error) {
	var roles []string
	if json.Unmarshal([]byte(encoded), &roles) != nil {
		return nil, ErrInvalidPrincipal
	}
	var mode string
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), subject).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return roles, nil
	}
	if err != nil {
		return nil, err
	}
	switch mode {
	case "legacy", "shadow":
		return roles, nil
	case "v2":
		return []string{}, nil
	default:
		return nil, ErrInvalidResource
	}
}
