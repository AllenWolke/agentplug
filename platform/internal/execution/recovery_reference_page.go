package execution

import (
	"context"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ReadRecoveryCheckpointPage is a read port for public State's authorized
// gateway. It reads only this Run's committed stop metadata, never values or
// arbitrary SQL. Page identity is bound to the current signed execution lease.
func (s *SQLStore) ReadRecoveryCheckpointPage(ctx context.Context, scope sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding, set contract.RecoveryCheckpointSetReference, offset, limit int) (contract.RecoveryCheckpointReferencePage, error) {
	deny := ErrStopEvidenceInvalid
	if set.Validate() != nil || offset < 0 || offset >= set.Count || limit < 1 || limit > contract.RecoveryCheckpointPageSize || scope.ValidateTrusted() != nil {
		return contract.RecoveryCheckpointReferencePage{}, deny
	}
	run, err := s.GetContext(ctx, scope.RunID)
	if err != nil || run.Scope != scope || run.Revision != lease.Revision || stopHash([]byte(run.LeaseToken)) != lease.TokenHash {
		return contract.RecoveryCheckpointReferencePage{}, deny
	}
	reference, err := s.CurrentRecoveryStopReference(ctx, run)
	if err != nil || reference == nil || reference.CheckpointSet == nil || *reference.CheckpointSet != set || !usesPagedRecovery(run) {
		return contract.RecoveryCheckpointReferencePage{}, deny
	}
	end := offset + limit
	if end > set.Count {
		end = set.Count
	}
	page := contract.RecoveryCheckpointReferencePage{Version: "recovery-checkpoint-page/v1", Set: set, Offset: offset,
		References: append([]contract.RecoveryCheckpointReference(nil), reference.Checkpoints[offset:end]...)}
	return page, nil
}
