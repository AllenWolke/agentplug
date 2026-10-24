package agentcoordination

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sqlutil"
)

// RenewUndelegatedRootAuthorityTx is only for an explicit waiting-Run owner
// renewal. The caller holds current IAM/session and the root Run UPDATE fence.
// Existing delegation edges make renewal unsafe and are always denied. Normal
// dispatch still uses immutable PinRootMachineAuthorityTx comparison.
func (s *SQLRouteStore) RenewUndelegatedRootAuthorityTx(ctx context.Context, tx *sql.Tx, previousEpoch uint64, next RootMachineAuthorityStamp) error {
	if s == nil || tx == nil || previousEpoch == 0 || !validRootMachineAuthorityStamp(next) || next.RootAuthorizationEpoch != previousEpoch {
		return ErrDenied
	}
	var delegated bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_agent_route WHERE parent_run_id=?)`), next.RootRunID).Scan(&delegated); err != nil {
		return err
	}
	if delegated {
		return ErrDenied
	}
	var saved RootMachineAuthorityStamp
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT root_run_id,root_installation_id,root_principal_type,root_principal_id,root_authorization_epoch,machine_principal_id,machine_run_epoch FROM platform_agent_delegation_root_authority WHERE root_run_id=? FOR UPDATE`), next.RootRunID).Scan(&saved.RootRunID, &saved.RootInstallationID, &saved.RootPrincipalType, &saved.RootPrincipalID, &saved.RootAuthorizationEpoch, &saved.MachinePrincipalID, &saved.MachineRunEpoch)
	if err != nil || !validRootMachineAuthorityStamp(saved) || saved.RootInstallationID != next.RootInstallationID || saved.RootPrincipalType != next.RootPrincipalType || saved.RootPrincipalID != next.RootPrincipalID || saved.RootAuthorizationEpoch != previousEpoch || saved.MachinePrincipalID != next.MachinePrincipalID || next.MachineRunEpoch < saved.MachineRunEpoch {
		return ErrDenied
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_agent_delegation_root_authority SET machine_run_epoch=? WHERE root_run_id=? AND root_authorization_epoch=? AND machine_principal_id=? AND machine_run_epoch=?`), next.MachineRunEpoch, next.RootRunID, saved.RootAuthorizationEpoch, saved.MachinePrincipalID, saved.MachineRunEpoch)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrDenied
	}
	return nil
}
