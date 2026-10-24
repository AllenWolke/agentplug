package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"
)

const (
	harnessPolicyPath          = "/internal/runtime/harness-policy"
	harnessReceiptQueryTimeout = 5 * time.Second
)

type harnessLoopLimits struct {
	MaxRounds         int    `json:"max_rounds"`
	MaxToolCalls      int    `json:"max_tool_calls"`
	MaxRepeatedCalls  int    `json:"max_repeated_calls"`
	MaxElapsedSeconds int    `json:"max_elapsed_seconds"`
	LimitBehavior     string `json:"limit_behavior"`
}

type harnessPublishedPolicy struct {
	Hash         string
	ServerTimeMS int64
	Limits       harnessLoopLimits
	RequestStart time.Time
}

func loadHarnessPublishedPolicy(ctx context.Context, port harnessPort) (harnessPublishedPolicy, error) {
	requestStart := time.Now()
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := port.Post(requestCtx, harnessPolicyPath, map[string]any{})
	if err != nil {
		return harnessPublishedPolicy{}, err
	}
	if len(response) != 4 || response["version"] != "harness-policy/v1" {
		return harnessPublishedPolicy{}, harnessError("HARNESS_POLICY_REJECTED")
	}
	hash, ok := response["policy_hash"].(string)
	if !ok || !validHarnessPolicyHash(hash) {
		return harnessPublishedPolicy{}, harnessError("HARNESS_POLICY_REJECTED")
	}
	serverTimeMS, ok := exactHarnessInteger(response["server_time_ms"])
	if !ok || serverTimeMS <= 0 {
		return harnessPublishedPolicy{}, harnessError("HARNESS_POLICY_REJECTED")
	}
	rawLimits, ok := response["limits"].(map[string]any)
	limits, valid := decodeHarnessLoopLimits(rawLimits)
	if !ok || !valid {
		return harnessPublishedPolicy{}, harnessError("HARNESS_POLICY_REJECTED")
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if serverTimeMS > maxInt64-int64(limits.MaxElapsedSeconds)*1000 {
		return harnessPublishedPolicy{}, harnessError("HARNESS_POLICY_REJECTED")
	}
	return harnessPublishedPolicy{Hash: hash, ServerTimeMS: serverTimeMS, Limits: limits, RequestStart: requestStart}, nil
}

func decodeHarnessLoopLimits(raw map[string]any) (harnessLoopLimits, bool) {
	var limits harnessLoopLimits
	if len(raw) != 5 {
		return limits, false
	}
	for _, field := range []string{"max_rounds", "max_tool_calls", "max_repeated_calls", "max_elapsed_seconds", "limit_behavior"} {
		if _, exists := raw[field]; !exists {
			return limits, false
		}
	}
	maxRounds, roundsOK := exactHarnessInteger(raw["max_rounds"])
	maxToolCalls, toolsOK := exactHarnessInteger(raw["max_tool_calls"])
	maxRepeatedCalls, repeatedOK := exactHarnessInteger(raw["max_repeated_calls"])
	maxElapsedSeconds, elapsedOK := exactHarnessInteger(raw["max_elapsed_seconds"])
	behavior, behaviorOK := raw["limit_behavior"].(string)
	if !roundsOK || maxRounds < 1 || maxRounds > 8 ||
		!toolsOK || maxToolCalls < 1 || maxToolCalls > 16 ||
		!repeatedOK || maxRepeatedCalls < 1 || maxRepeatedCalls > 4 ||
		!elapsedOK || maxElapsedSeconds < 10 || maxElapsedSeconds > 3600 ||
		!behaviorOK || (behavior != "error" && behavior != "incomplete") {
		return limits, false
	}
	limits.MaxRounds, limits.MaxToolCalls = int(maxRounds), int(maxToolCalls)
	limits.MaxRepeatedCalls, limits.MaxElapsedSeconds = int(maxRepeatedCalls), int(maxElapsedSeconds)
	limits.LimitBehavior = behavior
	return limits, true
}

func exactHarnessInteger(value any) (int64, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil
	case int:
		return int64(number), true
	case int64:
		return number, true
	case int32:
		return int64(number), true
	case uint64:
		if number > uint64(1<<63-1) {
			return 0, false
		}
		return int64(number), true
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || math.Abs(number) > 1<<53-1 {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
}

func validHarnessPolicyHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func (p harnessPublishedPolicy) newLoopDeadlineMS() int64 {
	return p.ServerTimeMS + int64(p.Limits.MaxElapsedSeconds)*1000
}

// Remaining uses the server's timestamp as its epoch and a local monotonic
// duration from before the read request. It never depends on the Agent host's
// wall clock, and errs on the restrictive side by including policy-read time.
func (p harnessPublishedPolicy) remaining(deadlineMS int64) time.Duration {
	if deadlineMS <= 0 || p.ServerTimeMS <= 0 || p.RequestStart.IsZero() {
		return 0
	}
	elapsedMS := time.Since(p.RequestStart).Milliseconds()
	if elapsedMS < 0 {
		return 0
	}
	remainingMS := deadlineMS - p.ServerTimeMS - elapsedMS
	if remainingMS <= 0 {
		return 0
	}
	return time.Duration(remainingMS) * time.Millisecond
}

func harnessOperationContext(parent context.Context, policy harnessPublishedPolicy, deadlineMS int64) (context.Context, context.CancelFunc, bool) {
	remaining := policy.remaining(deadlineMS)
	if remaining <= 0 {
		return nil, func() {}, false
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, true
}

func harnessReceiptContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), harnessReceiptQueryTimeout)
}

func harnessReadOnlyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, harnessReceiptQueryTimeout)
}

func harnessPolicyTimedOut(requestCtx, parent context.Context, policy harnessPublishedPolicy, deadlineMS int64) bool {
	return requestCtx != nil && errors.Is(requestCtx.Err(), context.DeadlineExceeded) && parent.Err() == nil && policy.remaining(deadlineMS) <= 0
}

func harnessRepeatDigest(name string, payload map[string]any) (string, error) {
	normalized, err := normalizeJSONValue(payload)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal([]any{name, normalized})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func harnessLimitOutput(previous map[string]any, finishReason string) map[string]any {
	output := map[string]any{
		"completion_status":  "incomplete",
		"termination_reason": "HARNESS_LIMIT_EXCEEDED",
		"finish_reason":      finishReason,
	}
	// Same canonical preserved set as harnessBudgetOutput and the Python/Java
	// harness: a round/tool/elapsed limit must not drop routing and model
	// attribution needed for billing and audit.
	for _, key := range []string{"text", "model", "usage", "billing", "run_budget", "prompt_template_hash", "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"} {
		if value, exists := previous[key]; exists {
			output[key] = value
		}
	}
	return output
}

func newHarnessState(inputHash string, messages []any, policy harnessPublishedPolicy) harnessState {
	return harnessState{
		Version: "harness-loop/v1", InputHash: inputHash, Phase: "model", Messages: messages,
		LoopPolicyHash: policy.Hash, LoopLimits: policy.Limits, LoopDeadlineMS: policy.newLoopDeadlineMS(),
		ToolRepeats: map[string]int{}, RepeatCountedCallID: "",
	}
}

// harnessPolicyFieldsPresent distinguishes pre-policy checkpoints from
// partial/corrupt policy metadata. A dispatched legacy state is upgraded only
// after its original read-only receipt has been consumed.
func harnessPolicyFieldsPresent(checkpoint json.RawMessage) (bool, error) {
	var envelope struct {
		Value map[string]json.RawMessage `json:"value"`
	}
	if json.Unmarshal(checkpoint, &envelope) != nil || envelope.Value == nil {
		return false, harnessError("HARNESS_STATE_REJECTED")
	}
	fields := []string{"loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats", "repeat_counted_call_id"}
	present := 0
	for _, field := range fields {
		if _, exists := envelope.Value[field]; exists {
			present++
		}
	}
	if present == 0 {
		return false, nil
	}
	if present != len(fields) {
		return false, harnessError("HARNESS_STATE_REJECTED")
	}
	return true, nil
}

func validateHarnessPolicyState(policy harnessPublishedPolicy, hash string, limits harnessLoopLimits, deadlineMS int64, repeats map[string]int, repeatCountedCallID string, phase string, pending []HarnessOperation) error {
	if !validHarnessPolicyHash(hash) || hash != policy.Hash || limits != policy.Limits || deadlineMS <= 0 || repeats == nil || len(repeats) > 16 {
		return harnessError("HARNESS_POLICY_CHANGED")
	}
	for key, count := range repeats {
		if !validHarnessPolicyHash(key) || count < 1 || count > limits.MaxRepeatedCalls {
			return harnessError("HARNESS_STATE_REJECTED")
		}
	}
	if repeatCountedCallID != "" {
		if (phase != "tool_dispatch" && phase != "approval_required") || len(pending) == 0 || pending[0].CallID != repeatCountedCallID {
			return harnessError("HARNESS_STATE_REJECTED")
		}
	}
	if (phase == "tool_dispatch" || phase == "approval_required") && len(pending) > 0 && repeatCountedCallID == "" {
		return harnessError("HARNESS_STATE_REJECTED")
	}
	return nil
}
