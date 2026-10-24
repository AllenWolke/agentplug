package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type failingPolicyDependency struct{ err error }

func (f failingPolicyDependency) Resolve(context.Context, sharedkernel.Scope, string) (policyasset.Snapshot, error) {
	return policyasset.Snapshot{}, f.err
}

func TestPolicyResolutionPreservesAbortCauseAndMasksPrivateMessage(t *testing.T) {
	for _, state := range []string{"40001", "40P01", "40003", "42501"} {
		t.Run(state, func(t *testing.T) {
			cause := &pgconn.PgError{Code: state, Message: "private-SQL-and-credential"}
			module := Module{policy: failingPolicyDependency{cause}}
			_, err := module.validatePolicy(context.Background(), capabilityContext())
			if !errors.Is(err, cause) || err.Error() != "policy snapshot unavailable" || strings.Contains(err.Error(), "private") {
				t.Fatal("typed dependency cause lost or private details exposed", err)
			}
			if sqlutil.IsTransactionRollback(err) != (state == "40001" || state == "40P01") {
				t.Fatal("ambiguous/error class became a retry permission", state)
			}
		})
	}
}
