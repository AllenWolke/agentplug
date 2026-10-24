package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type dispatchAuthorityFixture struct {
	failAt            string
	failure           error
	expected, current uint64
	allowed           bool
	calls             []string
}

func (f *dispatchAuthorityFixture) check(stage string) error {
	f.calls = append(f.calls, stage)
	if stage == f.failAt {
		return f.failure
	}
	return nil
}
func (f *dispatchAuthorityFixture) ExpectedAuthorizationEpoch(context.Context, sharedkernel.Scope) (uint64, error) {
	return f.expected, f.check("expected_epoch")
}
func (f *dispatchAuthorityFixture) CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error) {
	return f.current, f.check("current_epoch")
}
func (f *dispatchAuthorityFixture) AuthorizeConversationRun(context.Context, sharedkernel.Scope) (bool, error) {
	return f.allowed, f.check("current_grant")
}
func (f *dispatchAuthorityFixture) ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error {
	return f.check("pinned_target")
}
func (f *dispatchAuthorityFixture) authority() dispatchAuthority {
	return dispatchAuthority{execution: f, identity: f,
		ancestry: func(context.Context, sharedkernel.Scope) error { return f.check("ancestry") },
		pinRoot:  func(context.Context, sharedkernel.Scope) error { return f.check("root_machine") }}
}

type dispatchSQLWait struct{}

func (dispatchSQLWait) Error() string    { return "secret-provider-body" }
func (dispatchSQLWait) SQLState() string { return "55P03" }

func TestDispatchAuthorityPreservesWaitCauseWithoutGrantingOrDisclosing(t *testing.T) {
	for _, stage := range []string{"expected_epoch", "current_epoch", "current_grant", "root_machine", "pinned_target", "ancestry"} {
		for _, failure := range []error{context.DeadlineExceeded, context.Canceled, dispatchSQLWait{}, errors.New("secret-provider-body")} {
			t.Run(stage+"/"+failure.Error(), func(t *testing.T) {
				f := &dispatchAuthorityFixture{expected: 1, current: 1, allowed: true, failAt: stage, failure: failure}
				scope := sharedkernel.Scope{}
				if stage == "ancestry" {
					scope.ParentRunID = "parent"
				}
				err := f.authority().Authorize(context.Background(), scope)
				if err == nil || !errors.Is(err, failure) || strings.Contains(err.Error(), "secret") {
					t.Fatal("unfinished check was allowed, lost its cause, or disclosed details")
				}
				var wait interface{ SQLState() string }
				if _, ok := failure.(dispatchSQLWait); ok && (!errors.As(err, &wait) || wait.SQLState() != "55P03") {
					t.Fatal("SQL lock-wait classification lost")
				}
				if f.calls[len(f.calls)-1] != stage {
					t.Fatal("authority continued after an unfinished check")
				}
			})
		}
	}
}

func TestDispatchAuthorityRejectsCompletedDenialsAndChecksPinnedTarget(t *testing.T) {
	for _, variant := range []string{"allowed", "epoch_changed", "grant_denied", "target_denied", "ancestry_denied"} {
		t.Run(variant, func(t *testing.T) {
			f := &dispatchAuthorityFixture{expected: 1, current: 1, allowed: true}
			scope := sharedkernel.Scope{}
			switch variant {
			case "epoch_changed":
				f.current = 2
			case "grant_denied":
				f.allowed = false
			case "target_denied":
				f.failAt = "pinned_target"
				f.failure = errors.New("revoked")
			case "ancestry_denied":
				scope.ParentRunID = "parent"
				f.failAt = "ancestry"
				f.failure = errors.New("revoked")
			}
			err := f.authority().Authorize(context.Background(), scope)
			if (err == nil) != (variant == "allowed") {
				t.Fatal("completed authorization decision changed")
			}
			if err != nil && (errors.Is(err, context.DeadlineExceeded) || ancestryLockWait(err)) {
				t.Fatal("denial became retryable")
			}
			if variant == "allowed" && strings.Join(f.calls, ",") != "expected_epoch,current_epoch,current_grant,root_machine,pinned_target" {
				t.Fatal("allowed root skipped an authority boundary")
			}
		})
	}
}
