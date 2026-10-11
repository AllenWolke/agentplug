package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type browserRunStoreFixture struct {
	versionedCatalogStore
	sessionErr error
}

func (s browserRunStoreFixture) ValidateBrowserSession(_ context.Context, scope sharedkernel.Scope, id string, rev uint64) error {
	if id != "verified-family" || rev != 7 || scope.PrincipalID != s.principal.ID {
		return identity.ErrRefreshSessionRejected
	}
	return s.sessionErr
}

func TestVersionedRunHistoryAndCancelRequireCurrentSessionAndIndependentGrants(t *testing.T) {
	store, owner := businessReviewFixture()
	store.snapshot.Bindings[0].RoleCode = "operator"
	store.snapshot.Grants[0].Action = "history.read"
	fixture := browserRunStoreFixture{versionedCatalogStore: store}
	actor := execution.BrowserRunActor{Scope: sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "reviewer"}, AuthenticationSession: "verified-family", AuthenticationRevision: 7}
	ctx := context.Background()
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); err != nil {
		t.Fatal("independent explicit history permission required run", err)
	}
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "cancel"); !errors.Is(err, execution.ErrRunPermissionDenied) {
		t.Fatal("read grant implied cancel", err)
	}
	fixture.snapshot.Grants[0].DataScope = identity.DataScope{Type: "owner"}
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); !errors.Is(err, execution.ErrRunPermissionDenied) {
		t.Fatal("owner grant read another subject", err)
	}
	owner.PrincipalID = actor.Scope.PrincipalID
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); err != nil {
		t.Fatal("own history denied", err)
	}
	fixture.sessionErr = identity.ErrRefreshSessionRejected
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); !errors.Is(err, execution.ErrBrowserSessionInvalid) {
		t.Fatal("revoked family accepted", err)
	}
	fixture.sessionErr = errors.New("SQL unavailable")
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); !errors.Is(err, fixture.sessionErr) {
		t.Fatal("session outage fell back", err)
	}
	fixture.sessionErr = nil
	fixture.snapshot.Bindings = nil
	if err := (identityExecutionBrowserControl{store: fixture}).Authorize(ctx, owner, actor, "history.read"); !errors.Is(err, execution.ErrRunPermissionDenied) {
		t.Fatal("old admin role restored history", err)
	}
}
