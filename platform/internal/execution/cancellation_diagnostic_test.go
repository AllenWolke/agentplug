package execution

import (
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/compensation"
)

type diagnosticDatabaseError struct{}

func (diagnosticDatabaseError) Error() string {
	return "private query and credentials must not be logged"
}
func (diagnosticDatabaseError) SQLState() string { return "42501" }

func TestCancellationDiagnosticsUseBoundedInnermostLabels(t *testing.T) {
	for _, tc := range []struct {
		err         error
		phase, code string
	}{
		{stopPhaseError{"agent_stop_commit", stopPhaseError{"compensation_coverage", compensation.ErrConflict}}, "compensation_coverage", "COMPENSATION_CONFLICT"},
		{stopPhaseError{"compensation_enrollment", diagnosticDatabaseError{}}, "compensation_enrollment", "DATABASE_42501"},
		{stopPhaseError{"remote_transport", errors.New("token=private")}, "remote_transport", "REMOTE_STOP_UNCONFIRMED"},
	} {
		phase, code := stopDiagnostic(tc.err)
		if phase != tc.phase || code != tc.code {
			t.Fatalf("bounded diagnostic mismatch: %s %s", phase, code)
		}
	}
}
