package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type renewedAuthorityExecution struct {
	stopOnlyAuthorityExecution
	scope    sharedkernel.Scope
	epoch    uint64
	proofErr error
}

func (e *renewedAuthorityExecution) ExpectedAuthorizationEpoch(_ context.Context, scope sharedkernel.Scope) (uint64, error) {
	if scope != e.scope {
		return 0, errors.New("foreign durable scope")
	}
	return e.epoch, e.proofErr
}

func (e *renewedAuthorityExecution) ValidateEventRead(_ context.Context, scope sharedkernel.Scope, hash string) error {
	if scope != e.scope || hash != "original-policy" {
		return errors.New("source binding denied")
	}
	return nil
}

type independentActionIAM struct {
	run, history uint64
	deny         string
}

func (a independentActionIAM) PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error) {
	return identity.PermissionSnapshot{Mode: "legacy"}, nil
}
func (a independentActionIAM) CurrentAuthorizationEpoch(_ context.Context, _ sharedkernel.Scope, action string) (uint64, error) {
	if action == a.deny {
		return 0, errors.New("current permission revoked")
	}
	if action == "history.read" {
		return a.history, nil
	}
	return a.run, nil
}

func TestRenewedEventReadChecksIndependentCurrentRunAndHistoryGrants(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent", AgentVersionID: "original-version", PrincipalType: "user", PrincipalID: "caller", SessionID: "session", RunID: "original-run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	for _, variant := range []string{"independent epochs", "revoked run", "revoked history", "stale run", "invalid proof"} {
		t.Run(variant, func(t *testing.T) {
			e := &renewedAuthorityExecution{scope: scope, epoch: 2}
			iam := independentActionIAM{run: 2, history: 7}
			switch variant {
			case "revoked run":
				iam.deny = "run"
			case "revoked history":
				iam.deny = "history.read"
			case "stale run":
				iam.run = 3
			case "invalid proof":
				e.proofErr = errors.New("invalid proof")
			}
			a := capabilityExecutionAuthority{execution: e, identity: iam, catalog: stopOnlyAuthorityCatalog{expected: scope}}
			// The snapshot fixture leaves capability-resource grants to their
			// existing v2 tests. This exercises the public event authority method.
			err := a.AuthorizeEventRead(context.Background(), scope, "original-policy")
			if (err == nil) != (variant == "independent epochs") {
				t.Fatal("independent action authority boundary", err)
			}
		})
	}
}

func TestRenewedAuthorityPreservesOldScopeAndStillRejectsStaleOrRevokedIAM(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent", AgentVersionID: "original-version", PrincipalType: "user", PrincipalID: "caller", SessionID: "session", RunID: "original-run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
	for _, variant := range []string{"renewed", "stale", "revoked", "invalid proof", "foreign execution"} {
		t.Run(variant, func(t *testing.T) {
			e := &renewedAuthorityExecution{scope: scope, epoch: 2}
			iam := stopOnlyAuthorityIAM{epoch: 2}
			lookup := scope
			switch variant {
			case "stale":
				iam.epoch = 1
			case "revoked":
				iam.epoch = 3
			case "invalid proof":
				e.proofErr = errors.New("invalid authority receipt")
			case "foreign execution":
				lookup.AgentVersionID = "foreign"
			}
			a := capabilityExecutionAuthority{execution: e, identity: iam}
			err := a.AuthorizeCurrentRunEpoch(context.Background(), lookup)
			if (err == nil) != (variant == "renewed") {
				t.Fatal("current authority boundary failed", err)
			}
			if scope.AuthorizationEpoch != 1 {
				t.Fatal("original execution identity changed")
			}
		})
	}
}
