package capability

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Preserve the first failure as bounded enums. Error strings, SQL, provider
// output, inputs and credentials must never enter the audit or log fields.
// This observation grants no permission to retry or change an UNKNOWN result.
type toolFailureDiagnostic struct{ causeType, causeStage string }
type toolFailureDiagnosticKey struct{}

func classifyToolFailure(err error) toolFailureDiagnostic {
	result := toolFailureDiagnostic{causeType: "unclassified", causeStage: capabilityFailureDiagnostic(err)}
	if err == nil {
		return toolFailureDiagnostic{causeType: "none", causeStage: ""}
	}
	if code := sqlutil.SQLState(err); len(code) == 5 {
		valid := true
		for _, c := range code {
			valid = valid && (c >= '0' && c <= '9' || c >= 'A' && c <= 'Z')
		}
		if valid {
			result.causeType = "sqlstate_" + code
			return result
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		result.causeType = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		result.causeType = "context_cancelled"
	case errors.Is(err, ErrToolNotSubmitted):
		result.causeType = "confirmed_no_effect"
	case errors.Is(err, ErrToolInvocationConflict):
		result.causeType = "tool_fence_conflict"
	case errors.Is(err, ErrToolResultUnknown):
		result.causeType = "original_result_unknown"
	case errors.Is(err, usagecost.ErrBudgetScopeMismatch):
		result.causeType = "budget_scope_mismatch"
	case errors.Is(err, usagecost.ErrBudgetReservationConflict):
		result.causeType = "budget_reservation_conflict"
	case errors.Is(err, usagecost.ErrBudgetExceeded):
		result.causeType = "budget_exceeded"
	case fixedToolFailureCause(err, "platform context expired"):
		result.causeType = "context_expired"
	case result.causeStage == "SIGNED_EXECUTION" || result.causeStage == "SIGNED_POLICY":
		result.causeType = "signed_binding_rejected"
	}
	return result
}

func fixedToolFailureCause(err error, expected string) bool {
	for depth := 0; err != nil && depth < 16; depth++ {
		if err.Error() == expected {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
