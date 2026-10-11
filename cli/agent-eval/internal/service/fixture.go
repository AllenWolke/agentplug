package service

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func runFixture(ctx context.Context, r agentplatform.ExecuteRequest, c port) (map[string]any, error) {
	if r.InputSchema != "schema://agent-eval-simulation/input/v1" || r.IdempotencyKey == "" {
		return nil, errors.New("FIXTURE_INPUT_INVALID")
	}
	for key := range r.Input {
		if key != "scenario" && key != "untrusted_content" && key != "policy_snapshot" {
			return nil, errors.New("FIXTURE_INPUT_INVALID")
		}
	}
	scenario, _ := r.Input["scenario"].(string)
	content, _ := r.Input["untrusted_content"].(string)
	if len(content) > 48<<10 {
		return nil, errors.New("FIXTURE_INPUT_INVALID")
	}
	result := map[string]any{"schema": "schema://agent-eval-simulation/output/v1", "scenario": scenario, "synthetic": true, "side_effect_replayed": false}
	call := func(name, operation string) (map[string]any, error) {
		return c.Post(ctx, "/internal/tool/invoke", map[string]any{"name": name, "call_id": r.IdempotencyKey + ":" + operation, "payload": map[string]any{"scenario": operation}})
	}
	switch scenario {
	case "ambiguous":
		result["disposition"] = "clarification_required"
		return result, nil
	case "low_confidence_route":
		result["disposition"] = "handoff"
		return result, nil
	case "permission_boundary":
		_, err := call("api.eval_forbidden", "success")
		var denied *agentplatform.AppError
		if !errors.As(err, &denied) || (denied.Code != "TOOL_NOT_ALLOWED" && denied.Code != "TOOL_PERMISSION_DENIED" && denied.Code != "CAPABILITY_DENIED") {
			return nil, errors.New("FIXTURE_PERMISSION_DENIAL_UNCONFIRMED")
		}
		if c.ValidateCurrentExecution(ctx) != nil {
			return nil, errors.New("FIXTURE_PERMISSION_DENIAL_UNCONFIRMED")
		}
		result["disposition"] = "permission_denied"
		result["error_code"] = denied.Code
		return result, nil
	case "checkpoint":
		const schema = "schema://agent-eval-simulation/state/v1"
		loaded, err := c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "load", "namespace": "evaluation", "key": "fixture", "schema_id": schema, "revision": 0})
		if err != nil {
			return nil, errors.New("FIXTURE_CHECKPOINT_UNAVAILABLE")
		}
		var revision uint64
		if checkpoint, ok := loaded["checkpoint"].(map[string]any); ok {
			b, _ := json.Marshal(checkpoint["revision"])
			revision, _ = strconv.ParseUint(string(b), 10, 64)
			if checkpoint["schema_id"] != schema {
				return nil, errors.New("FIXTURE_CHECKPOINT_INVALID")
			}
		}
		if revision == 0 {
			_, err = c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "save", "namespace": "evaluation", "key": "fixture", "schema_id": schema, "expected_revision": 0, "idempotency_key": "fixture-state-v1", "value": map[string]any{"phase": "saved", "command": r.IdempotencyKey}})
			if err != nil {
				return nil, errors.New("FIXTURE_CHECKPOINT_UNAVAILABLE")
			}
		}
		verified, err := c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "load", "namespace": "evaluation", "key": "fixture", "schema_id": schema, "revision": 0})
		if err != nil {
			return nil, errors.New("FIXTURE_CHECKPOINT_UNAVAILABLE")
		}
		checkpoint, _ := verified["checkpoint"].(map[string]any)
		value, _ := checkpoint["value"].(map[string]any)
		if value["phase"] != "saved" || value["command"] != r.IdempotencyKey {
			return nil, errors.New("FIXTURE_CHECKPOINT_INVALID")
		}
		result["disposition"] = "checkpoint_roundtrip"
		result["process_recovery_proven"] = false
		return result, nil
	case "normal", "multistep", "tool_failure", "timeout", "unknown_side_effect", "injection", "long_context":
	default:
		return nil, errors.New("FIXTURE_INPUT_INVALID")
	}
	operation := "success"
	if scenario == "tool_failure" {
		operation = "failure"
	}
	if scenario == "timeout" {
		operation = "timeout"
	}
	if scenario == "unknown_side_effect" {
		operation = "unknown"
	}
	observation, err := call("api.eval_fixture", operation)
	if err != nil {
		// A bounded failed API call does not prove that a write rolled back.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if scenario != "tool_failure" && scenario != "timeout" {
			return nil, errors.New("FIXTURE_TOOL_UNAVAILABLE")
		}
		var failure *agentplatform.AppError
		if !errors.As(err, &failure) || failure.Code != "TOOL_PROVIDER_FAILED" || c.ValidateCurrentExecution(ctx) != nil {
			return nil, errors.New("FIXTURE_FAILURE_UNCONFIRMED")
		}
		result["disposition"] = "handoff"
		result["tool_error"] = true
		result["error_code"] = failure.Code
		return result, nil
	}
	if !verifiedFixtureObservation(observation, r.Scope.RunID, "api.eval_fixture", r.IdempotencyKey+":"+operation) {
		return nil, errors.New("FIXTURE_OBSERVATION_INVALID")
	}
	if scenario == "multistep" {
		second, e := call("api.eval_fixture", "success-2")
		err = e
		if err != nil {
			return nil, errors.New("FIXTURE_TOOL_UNAVAILABLE")
		}
		if !verifiedFixtureObservation(second, r.Scope.RunID, "api.eval_fixture", r.IdempotencyKey+":success-2") {
			return nil, errors.New("FIXTURE_OBSERVATION_INVALID")
		}
	}
	if scenario == "unknown_side_effect" {
		result["disposition"] = "handoff"
		return result, nil
	}
	if scenario == "injection" || scenario == "long_context" {
		result["untrusted_instructions_executed"] = false
		result["untrusted_bytes"] = len(content)
	}
	result["disposition"] = "completed"
	result["observation_received"] = observation != nil
	return result, nil
}

func verifiedFixtureObservation(out map[string]any, runID, tool, callID string) bool {
	observation, ok := out["observation"].(map[string]any)
	if !ok {
		return false
	}
	return observation["version"] == "runtime-observation/v1" && observation["run_id"] == runID && observation["tool_name"] == tool && observation["call_id"] == callID && observation["status"] == "succeeded"
}
