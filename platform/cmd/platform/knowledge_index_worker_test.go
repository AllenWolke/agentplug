package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
)

type testInternalTaskPhaseError struct {
	phase string
	cause error
}

func (e testInternalTaskPhaseError) Error() string             { return "safe test phase failure" }
func (e testInternalTaskPhaseError) Unwrap() error             { return e.cause }
func (e testInternalTaskPhaseError) InternalTaskPhase() string { return e.phase }

func TestKnowledgeIndexWorkerFailureCodeUsesPhaseAndTypedCauses(t *testing.T) {
	unknown := errors.New("private provider or SQL details")
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"execute", testInternalTaskPhaseError{phase: "execute", cause: unknown}, "INDEX_TASK_EXECUTION_FAILED"},
		{"execute-timeout", testInternalTaskPhaseError{phase: "execute", cause: context.DeadlineExceeded}, "INDEX_TASK_EXECUTION_TIMEOUT"},
		{"finalize-fence", testInternalTaskPhaseError{phase: "finalize", cause: errors.Join(execution.ErrExecutionOutcomeUnconfirmed, unknown)}, "INDEX_TASK_OUTCOME_FENCE_UNCONFIRMED"},
		{"authorization", testInternalTaskPhaseError{phase: "authorize", cause: unknown}, "INDEX_TASK_AUTHORIZATION_FAILED"},
		{"worker-cancel", context.Canceled, "INDEX_TASK_WORKER_STOPPING"},
		{"unknown", unknown, "INDEX_TASK_PENDING_RECONCILIATION"},
		{"admission-policy", errors.Join(unknown, &capability.KnowledgeModelError{Status: 403, Code: "POLICY_DENIED"}), "INDEX_TASK_POLICY_DENIED"},
		{"admission-workload", &capability.KnowledgeModelError{Status: 403, Code: "WORKLOAD_AUTHENTICATION_DENIED"}, "INDEX_TASK_WORKLOAD_AUTHENTICATION_DENIED"},
		{"private-code", &capability.KnowledgeModelError{Status: 502, Code: "secret=must-not-appear"}, "INDEX_TASK_MODEL_ADMISSION_FAILED"},
		{"secret", errors.Join(unknown, errIndexSecretUnavailable), "INDEX_TASK_WORKLOAD_SECRET_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := knowledgeIndexWorkerFailureCode(test.err); got != test.want {
				t.Fatalf("failure code = %q, want %q", got, test.want)
			}
		})
	}
}
