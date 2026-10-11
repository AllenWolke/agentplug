package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestEpochMemoIsScopedToItsAuthorizationTransaction(t *testing.T) {
	firstTx, secondTx := new(sql.Tx), new(sql.Tx)
	firstContext := withEpochMemo(context.Background(), firstTx)
	firstMemo := epochMemoFor(firstContext, firstTx)
	if firstMemo == nil {
		t.Fatal("authorization transaction memo was not installed")
	}
	firstMemo.hits["principal/action"] = 7
	if got := withEpochMemo(firstContext, firstTx); got != firstContext {
		t.Fatal("same transaction replaced its memo")
	}
	if epoch, ok := epochMemoFor(firstContext, firstTx).hits["principal/action"]; !ok || epoch != 7 {
		t.Fatal("same-transaction permission epoch was not retained")
	}
	if epochMemoFor(firstContext, secondTx) != nil {
		t.Fatal("a transaction reused an epoch memo owned by another transaction")
	}
	secondContext := withEpochMemo(firstContext, secondTx)
	secondMemo := epochMemoFor(secondContext, secondTx)
	if secondMemo == nil || secondMemo == firstMemo || len(secondMemo.hits) != 0 {
		t.Fatal("new transaction did not receive an empty permission memo")
	}
}

type delegatedExecutionFixture struct{ action string }

func (delegatedExecutionFixture) ValidateLiveLease(context.Context, sharedkernel.Scope, string, string, string) error {
	return nil
}
func (delegatedExecutionFixture) RenewCapabilityToken(context.Context, sharedkernel.Scope, string, string, string) (string, error) {
	return "renewed", nil
}
func (f delegatedExecutionFixture) CapabilityAuthorizationAction(context.Context, sharedkernel.Scope, string, string, string) (string, error) {
	return f.action, nil
}

type delegatedCatalogFixture struct{ target catalog.EvaluationAgentTarget }

func (f delegatedCatalogFixture) ResolveEvaluationAgentTarget(context.Context, sharedkernel.Scope, string, string) (catalog.EvaluationAgentTarget, error) {
	return f.target, nil
}

func TestDelegatedRunAuthorityRequiresTrustedAncestryAndKeepsManagementEpoch(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentInstanceID: "target-install", InstallationID: "target-install", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "user", SessionID: "s", RunID: "child", ParentRunID: "root", AuthorizationEpoch: 7, TraceID: "trace"}
	identityPort := capabilitySnapshotFixture{}
	target := catalog.EvaluationAgentTarget{AgentID: "agent", InstallationID: "target-install", AgentVersionID: "v1"}
	called := 0
	authority := capabilityExecutionAuthority{
		ancestry: func(_ context.Context, got sharedkernel.Scope) error {
			called++
			if got != scope {
				return errors.New("scope changed")
			}
			return nil
		},
		isDelegatedBusinessRun: func(_ context.Context, got sharedkernel.Scope) bool { return got == scope },
		execution:              delegatedExecutionFixture{action: "run"}, identity: identityPort, catalog: delegatedCatalogFixture{target: target},
	}
	if err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy"); err != nil || called != 1 {
		t.Fatalf("trusted delegated run was not admitted: err=%v ancestry_calls=%d", err, called)
	}
	authority.ancestry = nil
	if err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy"); err == nil {
		t.Fatal("delegated run without the private ancestry guard was admitted")
	}
	authority.ancestry = func(context.Context, sharedkernel.Scope) error { return nil }
	authority.execution = delegatedExecutionFixture{action: "policy.manage"}
	if err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy"); err == nil {
		t.Fatal("management action inherited the delegated run epoch")
	}
}

func TestDelegatedAncestryLockWaitIsNotRewrittenAsDenial(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentInstanceID: "target-install", InstallationID: "target-install", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "user", SessionID: "s", RunID: "child", ParentRunID: "root", AuthorizationEpoch: 7, TraceID: "trace"}
	authority := capabilityExecutionAuthority{
		execution: delegatedExecutionFixture{action: "run"}, identity: capabilitySnapshotFixture{}, catalog: delegatedCatalogFixture{target: catalog.EvaluationAgentTarget{AgentID: "agent", InstallationID: "target-install", AgentVersionID: "v1"}},
	}
	for _, wait := range []error{context.DeadlineExceeded, &pgconn.PgError{Code: "55P03"}, &pgconn.PgError{Code: "57014"}} {
		authority.ancestry = func(context.Context, sharedkernel.Scope) error { return wait }
		err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy")
		if !errors.Is(err, wait) || err.Error() == "delegated execution ancestry denied" {
			t.Fatalf("delegated ancestry lock wait was rewritten: got %v", err)
		}
	}
	authority.ancestry = func(context.Context, sharedkernel.Scope) error { return errors.New("finished denial") }
	if err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy"); err == nil || err.Error() != "delegated execution ancestry denied" {
		t.Fatalf("finished delegated denial must stay a denial, got %v", err)
	}
	authority.ancestry = func(context.Context, sharedkernel.Scope) error { return context.Canceled }
	if err := authority.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy"); err == nil || err.Error() != "delegated execution ancestry denied" || errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation must not be retried as an ancestor lock wait, got %v", err)
	}
}

func TestBudgetLockOrMismatchKeepsAncestorLockWait(t *testing.T) {
	if err := budgetLockOrMismatch(context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was rewritten: %v", err)
	}
	lock := &pgconn.PgError{Code: "55P03"}
	if err := budgetLockOrMismatch(lock); sqlutil.SQLState(err) != "55P03" {
		t.Fatalf("sqlstate 55P03 was rewritten: %v", err)
	}
	if err := budgetLockOrMismatch(&pgconn.PgError{Code: "57014"}); sqlutil.SQLState(err) != "57014" {
		t.Fatalf("sqlstate 57014 was rewritten: %v", err)
	}
	if err := budgetLockOrMismatch(errors.New("finished scope")); !errors.Is(err, usagecost.ErrBudgetScopeMismatch) {
		t.Fatalf("finished budget failure must stay a scope mismatch, got %v", err)
	}
	if err := budgetLockOrMismatch(nil); err != nil {
		t.Fatalf("nil budget error changed: %v", err)
	}
	if err := budgetLockOrMismatch(context.Canceled); !errors.Is(err, usagecost.ErrBudgetScopeMismatch) || errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation must not be retried as a budget lock wait, got %v", err)
	}
}
