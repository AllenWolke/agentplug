package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEvaluationInvocationErrorClassKeepsOnlySafeCategories(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "gRPC invalid response", err: fmt.Errorf("wrapped: %w", agentgateway.ErrGRPCInvalidResponse), want: "grpc_invalid_response"},
		{name: "contract app error", err: contract.AppError{Code: "AGENT_REJECTED", Message: "secret prompt must not be logged"}, want: "AGENT_REJECTED"},
		{name: "wrapped gRPC status", err: fmt.Errorf("wrapped: %w", status.Error(codes.DataLoss, "sensitive upstream body")), want: "grpc_dataloss"},
		{name: "schema failure", err: fmt.Errorf("wrapped: %w", contract.ErrSchemaValidation), want: "SCHEMA_VALIDATION_FAILED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := evaluationInvocationErrorClass(test.err)
			if got != test.want {
				t.Fatalf("error class = %q, want %q", got, test.want)
			}
			if got == test.err.Error() || got == "secret prompt must not be logged" || got == "sensitive upstream body" {
				t.Fatalf("error class leaked diagnostic contents: %q", got)
			}
		})
	}

	_, errorType := evaluationInvocationErrorClass(errors.New("arbitrary private value"))
	if errorType == "" || errorType == "arbitrary private value" {
		// The second result is an implementation type label, not message text.
		t.Fatalf("expected a safe concrete error type label, got %q", errorType)
	}
}
