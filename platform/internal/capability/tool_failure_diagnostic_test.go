package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestToolFailureCauseRetainsEnumsWithoutPrivateMessages(t *testing.T) {
	for _, tt := range []struct {
		cause error
		want  string
	}{
		{&pgconn.PgError{Code: "40001", Message: "private-sql-and-credential"}, "sqlstate_40001"},
		{&pgconn.PgError{Code: "40P01"}, "sqlstate_40P01"},
		{context.DeadlineExceeded, "deadline_exceeded"},
		{context.Canceled, "context_cancelled"},
		{usagecost.ErrBudgetScopeMismatch, "budget_scope_mismatch"},
		{usagecost.ErrBudgetReservationConflict, "budget_reservation_conflict"},
		{ErrToolInvocationConflict, "tool_fence_conflict"},
		{ErrToolResultUnknown, "original_result_unknown"},
		{errors.New("platform context expired"), "context_expired"},
		{errors.New("private-sql-and-credential"), "unclassified"},
		{&pgconn.PgError{Code: "secret"}, "unclassified"},
	} {
		got := classifyToolFailure(fmt.Errorf("private-sql-and-credential: %w", tt.cause))
		if got.causeType != tt.want || strings.Contains(got.causeType+got.causeStage, "private") || strings.Contains(got.causeType+got.causeStage, "secret") {
			t.Fatalf("unexpected or unsanitized cause classification: %+v", got)
		}
	}
	staged := &capabilityStageError{stage: "RUN_AUTHORITY", cause: &pgconn.PgError{Code: "40001"}}
	if got := classifyToolFailure(staged); got.causeType != "sqlstate_40001" || got.causeStage != "RUN_AUTHORITY" {
		t.Fatal("original stage or SQLSTATE lost", got)
	}
}
