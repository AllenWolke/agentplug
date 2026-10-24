package capability

import "github.com/lexagent/platform/internal/sharedkernel"

// Scope hashes identify exact persisted tool ledgers, including legacy rows
// whose receipt query cannot be decoded. Configure only before workers start.
func (s *SQLToolInvocationStore) SetAutomaticRecoveryHolds(holds sharedkernel.RecoveryHolds) error {
	if s == nil || s.recoveryHoldsConfigured {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	s.recoveryHolds, s.recoveryHoldsConfigured = holds, true
	return nil
}
