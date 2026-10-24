package capability

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestModelBudgetAuthoritiesPreserveExpiredContextWithoutGrantingAccess(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", AgentID: "agent", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentVersionID: "v1", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
	request := usagecost.ModelBudgetRequest{RunID: scope.RunID}
	for _, kind := range []string{"deadline", "cancelled", "live"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			if kind == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			} else if kind == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			ctx = context.WithValue(ctx, modelBudgetAdmissionKey{}, modelBudgetAdmission{Execution: skillRuntimeContext{Scope: scope, Check: func(context.Context) error { return sql.ErrTxDone }}, Request: request})
			_, _, executionErr := ModelBudgetExecutionAuthority(ctx, scope)
			_, _, _, _, admissionErr := ModelBudgetAdmissionAuthority(ctx, request)
			want := ctx.Err()
			if want == nil {
				want = usagecost.ErrBudgetScopeMismatch
			}
			if !errors.Is(executionErr, want) || !errors.Is(admissionErr, want) {
				t.Fatalf("authorities must not rewrite expired checks or allow unproven access: %v, %v", executionErr, admissionErr)
			}
		})
	}
}

func TestLedgerDiagnosticsUseSafeStableCategories(t *testing.T) {
	for _, item := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "deadline_exceeded"}, {context.Canceled, "context_cancelled"},
		{sql.ErrTxDone, "transaction_done"}, {usagecost.ErrBudgetScopeMismatch, "budget_scope_mismatch"},
		{usagecost.ErrBudgetReservationClosed, "budget_reservation_closed"},
		{usagecost.ErrBudgetReservationConflict, "budget_reservation_conflict"},
		{ErrModelInvocationConflict, "model_invocation_conflict"},
		{errors.New("secret-sql-and-credentials"), "unclassified"},
	} {
		if got := ledgerErrorType(item.err); got != item.want {
			t.Fatalf("got category %q, want %q", got, item.want)
		}
	}
}
