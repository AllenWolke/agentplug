package agentplatform

import (
	"context"
	"strings"
)

// InvokeTool preserves the exact call ID approved by the platform control plane.
// An empty confirmation token is valid only for tools not requiring approval.
// The SDK never signs approvals or automatically retries an unknown outcome.
func (c *CapabilityClient) InvokeTool(ctx context.Context, name, callID string, payload map[string]any, confirmationToken string) (map[string]any, error) {
	if strings.TrimSpace(name) == "" || len(name) > 128 || strings.TrimSpace(callID) == "" || len(callID) > 128 || payload == nil || len(confirmationToken) > 8192 {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "tool name, exact call ID and object payload are required"}
	}
	input := map[string]any{"name": name, "call_id": callID, "payload": payload}
	if confirmationToken != "" {
		input["confirmation_token"] = confirmationToken
	}
	return c.Post(ctx, "/internal/tool/invoke", input)
}
