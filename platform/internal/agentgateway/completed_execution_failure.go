package agentgateway

import (
	"errors"

	"github.com/lexagent/platform/internal/contract"
)

var ErrInvalidCompletedExecutionFailure = errors.New("invalid completed execution failure envelope")

// CompletedExecutionFailure carries a validated terminal failed response.
// Its embedded AppError remains discoverable with errors.As; unlike a bare
// AppError, this envelope preserves the protocol and RunID that the caller
// must bind to its current dispatch. It proves only that a terminal response
// was returned, not that prior side effects are settled or absent.
type CompletedExecutionFailure struct {
	Response contract.ExecuteResponse
}

func (e CompletedExecutionFailure) Error() string {
	if e.Response.Error == nil {
		return ErrInvalidCompletedExecutionFailure.Error()
	}
	return e.Response.Error.Error()
}

func (e CompletedExecutionFailure) Unwrap() error {
	if e.Response.Error == nil {
		return nil
	}
	return *e.Response.Error
}

// NewCompletedExecutionFailure accepts only a complete v2 terminal failed
// envelope without waiting handoff receipts. Transport callers still bind its
// RunID to the exact request before returning it.
func NewCompletedExecutionFailure(response contract.ExecuteResponse) (CompletedExecutionFailure, error) {
	if response.ProtocolVersion != contract.ProtocolVersion || response.RunID == "" || response.Status != "failed" ||
		response.Error == nil || response.Error.Code == "" || response.Error.Message == "" ||
		response.Handoff != nil || response.AgentGroupHandoff != nil {
		return CompletedExecutionFailure{}, ErrInvalidCompletedExecutionFailure
	}
	return CompletedExecutionFailure{Response: response}, nil
}
