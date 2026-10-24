package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestTransactionAbortSurvivesBudgetAuthorityAdapters(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", AgentID: "agent", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentVersionID: "v1", SessionID: "s", RunID: "r", TraceID: "trace", AuthorizationEpoch: 1}
	request := usagecost.ModelBudgetRequest{RunID: scope.RunID}
	for _, state := range []string{"40001", "40P01", "40003", "42501"} {
		t.Run(state, func(t *testing.T) {
			failure := &pgconn.PgError{Code: state}
			bound := skillRuntimeContext{Scope: scope, Check: func(context.Context) error { return failure }}
			ctx := context.WithValue(context.Background(), runtimeBudgetContextKey{}, bound)
			ctx = context.WithValue(ctx, agentRouteContextKey{}, bound)
			ctx = context.WithValue(ctx, modelBudgetAdmissionKey{}, modelBudgetAdmission{Execution: bound, Request: request})
			_, _, runtimeErr := RuntimeBudgetExecutionAuthority(ctx, scope)
			_, _, routeErr := AgentCoordinationAuthority(ctx, scope)
			_, _, modelErr := ModelBudgetExecutionAuthority(ctx, scope)
			_, _, _, _, admissionErr := ModelBudgetAdmissionAuthority(ctx, request)
			if sqlutil.IsTransactionRollback(failure) {
				for _, got := range []error{runtimeErr, routeErr, modelErr, admissionErr} {
					if !errors.Is(got, failure) {
						t.Fatalf("transaction abort became a denial: %v", got)
					}
				}
			} else if !errors.Is(runtimeErr, usagecost.ErrBudgetScopeMismatch) || !errors.Is(routeErr, agentcoordination.ErrDenied) || !errors.Is(modelErr, usagecost.ErrBudgetScopeMismatch) || !errors.Is(admissionErr, usagecost.ErrBudgetScopeMismatch) {
				t.Fatal("non-retriable failure admitted or lost closed denial")
			}
		})
	}
}

func TestBudgetAdmissionRetriesOnlyConfirmedSQLAborts(t *testing.T) {
	for _, state := range []string{"40001", "40P01", "40003", "42501"} {
		t.Run(state, func(t *testing.T) {
			failure := &pgconn.PgError{Code: state}
			store := &scriptedBudgetStore{script: []error{failure, nil}}
			_, err := reserveModelBudgetAdmission(context.Background(), store, usagecost.ModelBudgetRequest{RequestID: "same-request"})
			if sqlutil.IsTransactionRollback(failure) {
				if err != nil || len(store.reserved) != 2 || store.reserved[0] != store.reserved[1] || budgetAdmissionErrorType(failure) != "sqlstate_"+state {
					t.Fatal("admission did not reuse its attempt identity", err)
				}
			} else if !errors.Is(err, failure) || len(store.reserved) != 1 {
				t.Fatal("unproven SQL failure retried", err)
			}
		})
	}
}
