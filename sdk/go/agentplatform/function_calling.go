package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// GenerateWithFunctions runs a bounded model/tool loop using only the platform
// gateway. It never treats model output as user approval of a sensitive tool.
func (c *CapabilityClient) GenerateWithFunctions(ctx context.Context, input map[string]any, maxRounds int) (map[string]any, error) {
	if maxRounds < 1 || maxRounds > 8 {
		return nil, &AppError{Code: "FUNCTION_ROUND_LIMIT", Message: "function loop requires 1 to 8 rounds"}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid function input"}
	}
	var current map[string]any
	if json.Unmarshal(encoded, &current) != nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid function input"}
	}
	messages, ok := current["messages"].([]any)
	key, keyOK := current["idempotency_key"].(string)
	if !ok || len(messages) == 0 || !keyOK || key == "" {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "messages and stable idempotency key required"}
	}
	for round := 0; round < maxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current["messages"], current["idempotency_key"] = messages, functionStepKey(key, round, "model")
		result, err := c.Post(ctx, "/internal/model/generate", current)
		if err != nil {
			return nil, err
		}
		if result["completion_status"] == "incomplete" {
			return result, nil
		}
		calls, ok := result["tool_calls"].([]any)
		if !ok || len(calls) == 0 {
			if result["completion_status"] == "tool_calls" {
				return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "invalid tool calls"}
			}
			return result, nil
		}
		if round == maxRounds-1 || len(calls) > 32 {
			return nil, &AppError{Code: "FUNCTION_ROUND_LIMIT", Message: "tool round limit reached"}
		}
		bindings, ok := result["function_bindings"].(map[string]any)
		if !ok {
			return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "published function bindings missing"}
		}
		messages = append(messages, map[string]any{"role": "assistant", "content": result["text"], "tool_calls": calls})
		for _, raw := range calls {
			call, ok := raw.(map[string]any)
			if !ok {
				return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "invalid function call"}
			}
			function, ok := call["function"].(map[string]any)
			if !ok {
				return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "invalid function call"}
			}
			name, _ := function["name"].(string)
			tool, _ := bindings[name].(string)
			arguments, _ := function["arguments"].(string)
			id, _ := call["id"].(string)
			var payload map[string]any
			if tool == "" || id == "" || json.Unmarshal([]byte(arguments), &payload) != nil || payload == nil {
				return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "invalid function arguments"}
			}
			receipt, err := c.Post(ctx, "/internal/tool/invoke", map[string]any{"name": tool, "call_id": functionStepKey(key, round, id), "payload": payload, "confirmed": false})
			if err != nil {
				return nil, err
			}
			contextReceipt, err := functionToolContext(receipt, tool, functionStepKey(key, round, id))
			if err != nil {
				return nil, err
			}
			body, err := json.Marshal(contextReceipt)
			if err != nil {
				return nil, &AppError{Code: "FUNCTION_RESPONSE_INVALID", Message: "invalid tool receipt"}
			}
			messages = append(messages, map[string]any{"role": "tool", "tool_call_id": id, "content": string(body)})
		}
	}
	return nil, &AppError{Code: "FUNCTION_ROUND_LIMIT", Message: "tool round limit reached"}
}

func functionToolContext(receipt map[string]any, tool, callID string) (map[string]any, error) {
	raw, present := receipt["observation"]
	if !present {
		return receipt, nil
	} // Older published platform protocol.
	o, ok := raw.(map[string]any)
	if !ok || o["version"] != "runtime-observation/v1" || o["tool_name"] != tool || o["call_id"] != callID || !completedToolOutcome(o["status"]) || o["effect"] != "completed" || o["instruction_trust"] != "untrusted_data" {
		return nil, &AppError{Code: "TOOL_OBSERVATION_REJECTED", Message: "tool observation is invalid or incomplete"}
	}
	contextOutput, present := o["context_output"]
	encoded, err := json.Marshal(contextOutput)
	if !present || err != nil || len(encoded) > 2048 {
		return nil, &AppError{Code: "TOOL_OBSERVATION_REJECTED", Message: "tool context exceeds its public limit"}
	}
	return map[string]any{"version": o["version"], "tool_name": tool, "status": o["status"], "error_type": o["error_type"], "effect": o["effect"], "instruction_trust": "untrusted_data", "context_truncated": o["context_truncated"], "output_truncated": o["truncated"], "context_output": contextOutput}, nil
}

func completedToolOutcome(status any) bool {
	text, ok := status.(string)
	return ok && (text == "succeeded" || text == "failed" || text == "timeout" || text == "cancelled")
}

func functionStepKey(key string, round int, phase string) string {
	encoded, _ := json.Marshal([]any{key, round, phase})
	hash := sha256.Sum256(encoded)
	return "function-" + hex.EncodeToString(hash[:])
}
