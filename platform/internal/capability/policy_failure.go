package capability

// Preserve a dependency's typed cause for local transaction recovery without
// exposing its SQL or credential-bearing message to error consumers.
type policySnapshotUnavailableError struct{ cause error }

func (e *policySnapshotUnavailableError) Error() string { return "policy snapshot unavailable" }
func (e *policySnapshotUnavailableError) Unwrap() error { return e.cause }
