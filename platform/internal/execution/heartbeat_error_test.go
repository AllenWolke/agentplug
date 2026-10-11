package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

type heartbeatSQLFailure struct{ state string }

func (e heartbeatSQLFailure) Error() string    { return "secret=never-log-this" }
func (e heartbeatSQLFailure) SQLState() string { return e.state }

func TestHeartbeatFailureClassificationDoesNotDiscloseErrorDetails(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", fmt.Errorf("secret: %w", context.DeadlineExceeded), "deadline_exceeded"},
		{"cancel", context.Canceled, "context_cancelled"},
		{"lease", platformruntime.ErrLeaseConflict, "lease_conflict"},
		{"revision", platformruntime.ErrRevisionConflict, "revision_conflict"},
		{"missing", platformruntime.ErrRunNotFound, "run_not_found"},
		{"sql", fmt.Errorf("secret: %w", heartbeatSQLFailure{"55P03"}), "sqlstate_55P03"},
		{"untrusted_state", heartbeatSQLFailure{"key=secret"}, "database_unclassified"},
		{"untrusted_short_state", heartbeatSQLFailure{"a\nxxx"}, "database_unclassified"},
		{"unknown", errors.New("secret=never-log-this"), "database_unclassified"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := heartbeatErrorType(item.err); got != item.want {
				t.Fatalf("classification = %q, want %q", got, item.want)
			}
		})
	}
}
