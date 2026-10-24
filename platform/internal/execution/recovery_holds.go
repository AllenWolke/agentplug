package execution

import "github.com/lexagent/platform/internal/sharedkernel"

// SetAutomaticRecoveryHolds is startup-only operator configuration, not an
// Agent or browser request. Holding old Runs cannot authorize new dispatch.
func (m *Module) SetAutomaticRecoveryHolds(holds sharedkernel.RecoveryHolds) error {
	if m == nil || m.recoveryHoldsConfigured {
		return sharedkernel.ErrAutomaticRecoveryHeld
	}
	m.recoveryHolds, m.recoveryHoldsConfigured = holds, true
	if m.dispatcher != nil {
		m.dispatcher.recoveryHolds = holds
	}
	return nil
}
