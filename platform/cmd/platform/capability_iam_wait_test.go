package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type capabilityEpochWaitFixture struct{ err error }

func (f capabilityEpochWaitFixture) CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error) {
	return 0, f.err
}

func TestCapabilityEpochWaitRemainsUnfinishedAdmission(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "s", RunID: "r", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
	ctx := sharedkernel.WithExecutionLease(context.Background(), sharedkernel.ExecutionLeaseBinding{Revision: 7, TokenHash: strings.Repeat("a", 64)})
	for _, source := range []error{&pgconn.PgError{Code: "55P03"}, &pgconn.PgError{Code: "57014"}, context.DeadlineExceeded, context.Canceled, errors.New("revoked")} {
		a := capabilityExecutionAuthority{identity: capabilityEpochWaitFixture{err: source}, execution: &stopOnlyAuthorityExecution{action: "run"}, catalog: stopOnlyAuthorityCatalog{expected: scope}}
		for _, check := range []func() error{
			func() error {
				return a.AuthorizeCapability(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64))
			},
			func() error { return a.AuthorizeCurrentRunEpoch(ctx, scope) },
		} {
			err := check()
			if err == nil || ancestryLockWait(err) != ancestryLockWait(source) {
				t.Fatal("IAM wait converted to finished denial or revoked authority retried", source, err)
			}
			if ancestryLockWait(source) && !errors.Is(err, source) {
				t.Fatal("original admission cause lost", err)
			}
		}
	}
}
