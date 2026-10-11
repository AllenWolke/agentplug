package capability

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSkillRuntimeAuthorityKeepsBudgetAdmissionWait(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", RunID: "child", ParentRunID: "root"}
	for _, wait := range []error{context.DeadlineExceeded, &pgconn.PgError{Code: "55P03"}, &pgconn.PgError{Code: "57014"}} {
		ctx := context.WithValue(context.Background(), skillRuntimeContextKey{}, skillRuntimeContext{
			Scope: scope, Policy: policyasset.Snapshot{}, Check: func(context.Context) error { return wait },
		})
		_, _, err := SkillRuntimeAuthority(ctx, scope)
		if !errors.Is(err, wait) || errors.Is(err, ErrSkillDenied) {
			t.Fatalf("skill runtime authority rewrote an admission lock wait: %v", err)
		}
	}
	denied := context.WithValue(context.Background(), skillRuntimeContextKey{}, skillRuntimeContext{
		Scope: scope, Check: func(context.Context) error { return errors.New("finished denial") },
	})
	if _, _, err := SkillRuntimeAuthority(denied, scope); !errors.Is(err, ErrSkillDenied) {
		t.Fatalf("finished skill check must stay denied, got %v", err)
	}
	canceled := context.WithValue(context.Background(), skillRuntimeContextKey{}, skillRuntimeContext{
		Scope: scope, Check: func(context.Context) error { return context.Canceled },
	})
	if _, _, err := SkillRuntimeAuthority(canceled, scope); !errors.Is(err, ErrSkillDenied) || errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation must not be retried as a skill admission wait, got %v", err)
	}
}

func TestSkillTransactionAuthorizeKeepsBudgetAdmissionWait(t *testing.T) {
	scope := sharedkernel.Scope{RunID: "child"}
	store := &SQLSkillStore{authorize: func(context.Context, *sql.Tx, string, sharedkernel.Scope, string, string) error {
		return context.DeadlineExceeded
	}}
	unit := &skillSQLTransaction{scope: scope, store: store}
	if err := unit.Authorize(context.Background(), "skill.load", scope, "skill", "v1"); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSkillDenied) {
		t.Fatalf("skill transaction authorize rewrote a lock wait: %v", err)
	}
	store.authorize = func(context.Context, *sql.Tx, string, sharedkernel.Scope, string, string) error {
		return &pgconn.PgError{Code: "55P03"}
	}
	if err := unit.Authorize(context.Background(), "skill.load", scope, "skill", "v1"); !budgetAdmissionDeferred(err) {
		t.Fatalf("skill transaction authorize rewrote sqlstate 55P03: %v", err)
	}
	store.authorize = func(context.Context, *sql.Tx, string, sharedkernel.Scope, string, string) error {
		return errors.New("finished denial")
	}
	if err := unit.Authorize(context.Background(), "skill.load", scope, "skill", "v1"); !errors.Is(err, ErrSkillDenied) {
		t.Fatalf("finished skill authorize must stay denied, got %v", err)
	}
}
