package compensation

import "github.com/lexagent/platform/internal/sharedkernel"

// Startup-only deployment holds fence queue admission and finalization. The
// existing effect records, receipts, leases and unknown phases remain intact.
func (s *SQLStore) SetAutomaticRecoveryHolds(holds sharedkernel.RecoveryHolds) error {
	if s == nil || s.recoveryHoldsConfigured {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	s.recoveryHolds, s.recoveryHoldsConfigured = holds, true
	return nil
}
