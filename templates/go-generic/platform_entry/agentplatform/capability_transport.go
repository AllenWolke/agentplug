package agentplatform

import (
	"context"
	"errors"
	"time"
)

// SendLimiter is acquired at each physical HTTP send, including renewal and
// receipt lookup. Implementations may share sockets/counters, never IAM state.
type SendLimiter interface {
	Acquire(context.Context) (func(), error)
}
type CapabilityObservation struct {
	Path   string
	WallMS float64
	Status string
}
type capabilityTransportFailure struct{ cause error }

func (e *capabilityTransportFailure) Error() string { return "capability transport observation lost" }
func (e *capabilityTransportFailure) Unwrap() error { return e.cause }

func (c *CapabilityClient) recoverToolObservation(ctx context.Context, path string, input map[string]any, result map[string]any, original error) (map[string]any, error) {
	var lost *capabilityTransportFailure
	if original == nil || path != "/internal/tool/invoke" || !errors.As(original, &lost) {
		return result, original
	}
	if ctx.Err() != nil {
		return nil, publicError("TOOL_RESULT_UNKNOWN")
	}
	name, named := input["name"].(string)
	id, identified := input["call_id"].(string)
	payload, object := input["payload"].(map[string]any)
	if !named || name == "" || !identified || id == "" || !object {
		return nil, publicError("TOOL_RESULT_UNKNOWN")
	}
	command := map[string]any{"name": name, "call_id": id, "payload": payload}
	if token, ok := input["confirmation_token"].(string); ok && token != "" {
		command["confirmation_token"] = token
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	receipt, err := c.Post(readCtx, "/internal/tool/receipt", command)
	if err != nil {
		var app *AppError
		if errors.As(err, &app) && (app.Code == "TOOL_CONFIRMATION_REQUIRED" || app.Code == "MODEL_BUDGET_EXCEEDED") {
			return nil, publicError("CAPABILITY_DENIED")
		}
		if AuthorityFailure(err) {
			return nil, err
		}
		return nil, publicError("TOOL_RESULT_UNKNOWN")
	}
	if receipt["version"] != "tool-receipt/v1" || receipt["tool_name"] != name || receipt["call_id"] != id {
		return nil, publicError("TOOL_RECEIPT_REJECTED")
	}
	if receipt["status"] != "completed" {
		return nil, publicError("TOOL_RESULT_UNKNOWN")
	}
	value, ok := receipt["receipt"].(map[string]any)
	observation, valid := value["observation"].(map[string]any)
	_, hasData := value["data"]
	if !ok || !valid || !hasData || observation["version"] != "runtime-observation/v1" || observation["tool_name"] != name || observation["call_id"] != id || observation["status"] != "succeeded" || observation["effect"] != "completed" || observation["instruction_trust"] != "untrusted_data" {
		return nil, publicError("TOOL_RECEIPT_REJECTED")
	}
	return value, nil
}

type capabilityHTTPFailure struct {
	app    *AppError
	status int
}

func (e *capabilityHTTPFailure) Error() string   { return e.app.Error() }
func (e *capabilityHTTPFailure) Unwrap() error   { return e.app }
func (e *capabilityHTTPFailure) HTTPStatus() int { return e.status }
