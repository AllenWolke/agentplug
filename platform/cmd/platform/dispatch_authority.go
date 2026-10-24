package main

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type dispatchExecutionAuthority interface {
	ExpectedAuthorizationEpoch(context.Context, sharedkernel.Scope) (uint64, error)
	ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error
}

type dispatchIdentityAuthority interface {
	CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error)
	AuthorizeConversationRun(context.Context, sharedkernel.Scope) (bool, error)
}

// A fixed public message retains the internal cause for the heartbeat's bounded
// lock-wait handling. Never infer an authorization denial from an unfinished read.
type dispatchAuthorityFailure struct {
	stage string
	cause error
}

func (e *dispatchAuthorityFailure) Error() string {
	return "execution authority unavailable: " + e.stage
}
func (e *dispatchAuthorityFailure) Unwrap() error { return e.cause }

type dispatchAuthority struct {
	execution dispatchExecutionAuthority
	identity  dispatchIdentityAuthority
	ancestry  func(context.Context, sharedkernel.Scope) error
	pinRoot   func(context.Context, sharedkernel.Scope) error
}

func (a dispatchAuthority) Authorize(ctx context.Context, scope sharedkernel.Scope) error {
	fail := func(stage string, cause error) error { return &dispatchAuthorityFailure{stage, cause} }
	if a.execution == nil || a.identity == nil {
		return fail("configuration", nil)
	}
	if scope.ParentRunID != "" {
		if a.ancestry == nil {
			return fail("ancestry", nil)
		}
		if err := a.ancestry(ctx, scope); err != nil {
			return fail("ancestry", err)
		}
	} else {
		expected, err := a.execution.ExpectedAuthorizationEpoch(ctx, scope)
		if err != nil {
			return fail("expected_epoch", err)
		}
		epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, "run")
		if err != nil {
			return fail("current_epoch", err)
		}
		if epoch != expected {
			return fail("epoch_changed", nil)
		}
		allowed, err := a.identity.AuthorizeConversationRun(ctx, scope)
		if err != nil {
			return fail("current_grant", err)
		}
		if !allowed {
			return fail("grant_denied", nil)
		}
		if a.pinRoot != nil {
			if err := a.pinRoot(ctx, scope); err != nil {
				return fail("root_machine", err)
			}
		}
	}
	if err := a.execution.ValidatePinnedRunTarget(ctx, scope); err != nil {
		return fail("pinned_target", err)
	}
	return nil
}
