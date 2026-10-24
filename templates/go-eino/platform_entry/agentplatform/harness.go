package agentplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const HarnessStateSchema = "schema://agentplug/harness-loop/v1"
const ExtendedHarnessStateSchema = "schema://agentplug/harness-loop/v2"

type HarnessOptions struct {
	ExtensionID             string
	DeadlineMS              int64
	ActionValidator         func(map[string]any, map[string]any) bool
	ProgressEvaluator       func(map[string]any, map[string]any) (map[string]any, error)
	Key                     string
	MaxRounds, MaxToolCalls int
	// Delivered by the human control plane for the currently pending operation.
	// Never written into checkpoints.
	ConfirmationToken string
}

type HarnessOperation struct {
	RunID       string         `json:"run_id,omitempty"`
	Name        string         `json:"name"`
	CallID      string         `json:"call_id"`
	Payload     map[string]any `json:"payload"`
	ModelCallID string         `json:"model_call_id"`
}

type HarnessResult struct {
	Execution map[string]any    `json:"execution,omitempty"`
	Status    string            `json:"status"`
	Pending   *HarnessOperation `json:"pending,omitempty"`
	Output    map[string]any    `json:"output,omitempty"`
}

type harnessState struct {
	ExtensionID         string                         `json:"extension_id,omitempty"`
	Observations        []map[string]any               `json:"observations,omitempty"`
	ModelReceipts       []map[string]any               `json:"model_receipts,omitempty"`
	Version             string                         `json:"version"`
	InputHash           string                         `json:"input_hash"`
	Phase               string                         `json:"phase"`
	Round               int                            `json:"round"`
	ToolCount           int                            `json:"tool_count"`
	Messages            []any                          `json:"messages"`
	Pending             []HarnessOperation             `json:"pending,omitempty"`
	Output              map[string]any                 `json:"output,omitempty"`
	PromptHash          string                         `json:"prompt_hash,omitempty"`
	ContextSourceHash   string                         `json:"context_source_hash,omitempty"`
	ModelRequest        map[string]any                 `json:"model_request,omitempty"`
	SkillBindings       map[string]harnessSkillBinding `json:"skill_bindings,omitempty"`
	LoopPolicyHash      string                         `json:"loop_policy_hash"`
	LoopLimits          harnessLoopLimits              `json:"loop_limits"`
	LoopDeadlineMS      int64                          `json:"loop_deadline_ms"`
	ToolRepeats         map[string]int                 `json:"tool_repeats"`
	RepeatCountedCallID string                         `json:"repeat_counted_call_id"`
}

type harnessPort interface {
	Post(context.Context, string, map[string]any) (map[string]any, error)
	LoadCheckpoint(context.Context, string, string, string, uint64) (map[string]any, error)
	SaveCheckpoint(context.Context, string, string, string, string, uint64, map[string]any) (map[string]any, error)
}

// RunHarness persists model/tool boundaries through the governed checkpoint API.
// Dispatch interrupted before its receipt was persisted stops for reconciliation;
// it never guesses that a failed transport means no side effect occurred.
func (c *CapabilityClient) RunHarness(ctx context.Context, input map[string]any, options HarnessOptions) (HarnessResult, error) {
	result, err := runHarness(ctx, c, input, options)
	if err == nil && result.Pending != nil {
		c.mu.Lock()
		result.Pending.RunID, _ = c.context["task_id"].(string)
		c.mu.Unlock()
	}
	return result, err
}

func harnessError(code string) error {
	return &AppError{Code: code, Message: "harness stopped at a governed boundary", Retryable: false}
}

func harnessBudgetExhausted(result map[string]any) (bool, error) {
	raw, exists := result["run_budget"]
	if !exists {
		return false, nil
	}
	budget, valid := raw.(map[string]any)
	exhausted, boolean := budget["exhausted"].(bool)
	exceeded, exceededBoolean := budget["exceeded"].(bool)
	root, rootValid := budget["root_run_id"].(string)
	if !valid || budget["version"] != "run-tree-budget/v1" || !boolean || !exceededBoolean || !rootValid || root == "" {
		return false, harnessError("HARNESS_BUDGET_REJECTED")
	}
	return exhausted || exceeded, nil
}

func harnessBudgetOutput(previous map[string]any, reason string) map[string]any {
	output := map[string]any{"completion_status": "incomplete", "finish_reason": reason}
	// The preserved field set is the cross-language canonical set: Python and
	// Java harness keep routing/model attribution on budget-terminated outputs,
	// so a Go run cannot lose billing attribution at the same boundary.
	for _, key := range []string{"text", "model", "usage", "billing", "run_budget", "prompt_template_hash", "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"} {
		if value, exists := previous[key]; exists {
			output[key] = value
		}
	}
	if reason == "budget_exhausted" {
		output["termination_reason"] = "MODEL_BUDGET_EXCEEDED"
	}
	return output
}

func isHarnessBudgetDenial(err error) bool {
	var app *AppError
	return errors.As(err, &app) && app.Code == "MODEL_BUDGET_EXCEEDED"
}

func runHarness(ctx context.Context, port harnessPort, input map[string]any, o HarnessOptions) (HarnessResult, error) {
	if o.Key == "" || o.MaxRounds < 1 || o.MaxRounds > 8 || o.MaxToolCalls < 1 || o.MaxToolCalls > 16 || len(o.ConfirmationToken) > 8192 {
		return HarnessResult{}, harnessError("HARNESS_CONFIG_INVALID")
	}
	extended := o.ExtensionID != "" || o.DeadlineMS != 0 || o.ActionValidator != nil || o.ProgressEvaluator != nil
	namespace, stateSchema := "harness", HarnessStateSchema
	if extended {
		if !regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`).MatchString(o.ExtensionID) || o.DeadlineMS < 0 || o.DeadlineMS > 1<<53-1 {
			return HarnessResult{}, harnessError("HARNESS_CONFIG_INVALID")
		}
		namespace, stateSchema = "harness-v2", ExtendedHarnessStateSchema
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return HarnessResult{}, err
	}
	var current map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&current) != nil {
		return HarnessResult{}, harnessError("REQUEST_INVALID")
	}
	initial, ok := current["messages"].([]any)
	key, _ := current["idempotency_key"].(string)
	if !ok || len(initial) == 0 || key == "" {
		return HarnessResult{}, harnessError("REQUEST_INVALID")
	}
	requestedPromptHash, promptHashProvided := input["prompt_template_hash"]
	requestedPromptHashText, requestedPromptHashIsString := requestedPromptHash.(string)
	skillValue, skillPresent := current["skill_requests"]
	skillRequests, err := harnessSkillRequests(skillValue, skillPresent)
	if err != nil {
		return HarnessResult{}, err
	}
	delete(current, "skill_requests") // SDK orchestration metadata is not a model parameter.
	delete(current, "skill_bindings") // Only verified disclosures can supply these dependencies.
	bound, _ := json.Marshal([]any{input, o.MaxRounds, o.MaxToolCalls})
	if extended {
		var deadline any
		if o.DeadlineMS != 0 {
			deadline = o.DeadlineMS
		}
		bound, err = publicJSON([]any{input, o.MaxRounds, o.MaxToolCalls, o.ExtensionID, o.ActionValidator != nil, o.ProgressEvaluator != nil, deadline})
		if err != nil {
			return HarnessResult{}, err
		}
	}
	digest := sha256.Sum256(bound)
	inputHash := hex.EncodeToString(digest[:])
	policy, err := loadHarnessPublishedPolicy(ctx, port)
	if err != nil {
		return HarnessResult{}, err
	}
	effectiveMaxRounds := min(o.MaxRounds, policy.Limits.MaxRounds)
	effectiveMaxToolCalls := min(o.MaxToolCalls, policy.Limits.MaxToolCalls)
	s := newHarnessState(inputHash, initial, policy)
	if extended {
		s.Version = "harness-loop/v2"
		s.ExtensionID = o.ExtensionID
		s.Observations = []map[string]any{}
		s.ModelReceipts = []map[string]any{}
	}
	if o.DeadlineMS != 0 {
		s.LoopDeadlineMS = min(s.LoopDeadlineMS, o.DeadlineMS)
	}
	delete(current, "deadline_ms")
	loadCtx, loadCancel := harnessReadOnlyContext(ctx)
	loaded, err := port.LoadCheckpoint(loadCtx, namespace, o.Key, stateSchema, 0)
	loadCancel()
	if err != nil {
		return HarnessResult{}, err
	}
	if err := ValidateRuntimeRecoveryCheckpoint(ctx, namespace, o.Key, stateSchema, loaded); err != nil {
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	if loaded["checkpoint"] == nil {
		if err := AuthorizeRuntimeRecoveryStart(ctx, namespace, o.Key, stateSchema, s.InputHash); err != nil {
			return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
		}
	}
	var revision uint64
	var checkpointHasPromptHash bool
	var legacyPolicyState bool
	var policyStateMismatch bool
	var policyValidationErr error
	if cp, present := loaded["checkpoint"]; present && cp != nil {
		raw, _ := json.Marshal(cp)
		legacy, fieldErr := harnessPolicyFieldsPresent(raw)
		if fieldErr != nil {
			return HarnessResult{}, fieldErr
		}
		legacyPolicyState = !legacy
		var promptField struct {
			Value map[string]json.RawMessage `json:"value"`
		}
		if json.Unmarshal(raw, &promptField) == nil && promptField.Value != nil {
			_, checkpointHasPromptHash = promptField.Value["prompt_hash"]
		}
		var record struct {
			Revision uint64       `json:"revision"`
			Value    harnessState `json:"value"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&record) != nil || record.Revision == 0 || record.Value.Version != s.Version || record.Value.InputHash != s.InputHash {
			return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
		}
		revision, s = record.Revision, record.Value
		if !legacyPolicyState {
			if err := validateHarnessPolicyState(policy, s.LoopPolicyHash, s.LoopLimits, s.LoopDeadlineMS, s.ToolRepeats, s.RepeatCountedCallID, s.Phase, s.Pending); err != nil {
				if s.Phase != "model_dispatch" && s.Phase != "tool_dispatch" {
					return HarnessResult{}, err
				}
				policyStateMismatch = true
				policyValidationErr = err
			}
		}
	}
	if extended && (s.ExtensionID != o.ExtensionID || len(s.Observations) > 16 || len(s.ModelReceipts) > 8 || s.Observations == nil || s.ModelReceipts == nil) {
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	if o.DeadlineMS != 0 && s.LoopDeadlineMS > o.DeadlineMS {
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	if s.Round < 0 || s.Round > 8 || s.ToolCount < 0 || s.ToolCount > 16 || len(s.Pending) > 16 || len(s.Pending)+s.ToolCount > 16 || len(s.Messages) == 0 {
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	switch s.Phase {
	case "model", "model_dispatch", "done":
		if len(s.Pending) != 0 {
			return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
		}
	case "tool", "approval_required", "tool_dispatch":
		if len(s.Pending) == 0 {
			return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
		}
	default:
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	if legacyPolicyState && s.ToolCount > 0 && s.Phase != "model_dispatch" && s.Phase != "tool_dispatch" {
		return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
	}
	if promptHashProvided && (!requestedPromptHashIsString || requestedPromptHashText == "" ||
		(revision > 0 && checkpointHasPromptHash && s.PromptHash != requestedPromptHashText)) {
		return HarnessResult{}, harnessError("HARNESS_CONTEXT_REJECTED")
	}
	saveAt := func(saveCtx context.Context) error {
		if revision >= 63 {
			return harnessError("HARNESS_STATE_LIMIT")
		}
		raw, err := json.Marshal(s)
		if err != nil {
			return err
		}
		var value map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&value) != nil {
			return harnessError("HARNESS_STATE_REJECTED")
		}
		if extended {
			value["observations"], value["model_receipts"] = s.Observations, s.ModelReceipts
		}
		result, err := port.SaveCheckpoint(saveCtx, namespace, o.Key, stateSchema, fmt.Sprintf("loop-%d", revision+1), revision, value)
		if err != nil {
			return err
		}
		raw, _ = json.Marshal(result["checkpoint"])
		var receipt struct {
			Revision uint64 `json:"revision"`
		}
		if json.Unmarshal(raw, &receipt) != nil || receipt.Revision != revision+1 {
			return harnessError("HARNESS_STATE_REJECTED")
		}
		revision++
		return nil
	}
	save := func() error {
		saveCtx, saveCancel, allowed := harnessOperationContext(ctx, policy, s.LoopDeadlineMS)
		if !allowed {
			return harnessError("HARNESS_LIMIT_EXCEEDED")
		}
		defer saveCancel()
		return saveAt(saveCtx)
	}
	saveTerminal := func() error {
		terminalCtx, terminalCancel := harnessReceiptContext(ctx)
		defer terminalCancel()
		return saveAt(terminalCtx)
	}
	setCurrentPolicy := func() {
		s.LoopPolicyHash = policy.Hash
		s.LoopLimits = policy.Limits
		s.LoopDeadlineMS = policy.newLoopDeadlineMS()
		if o.DeadlineMS != 0 {
			s.LoopDeadlineMS = min(s.LoopDeadlineMS, o.DeadlineMS)
		}
		if s.ToolRepeats == nil {
			s.ToolRepeats = map[string]int{}
		}
	}
	refreshPolicyForLegacy := func() error {
		latest, err := loadHarnessPublishedPolicy(ctx, port)
		if err != nil {
			return err
		}
		policy = latest
		effectiveMaxRounds = min(o.MaxRounds, policy.Limits.MaxRounds)
		effectiveMaxToolCalls = min(o.MaxToolCalls, policy.Limits.MaxToolCalls)
		setCurrentPolicy()
		return nil
	}
	finishForLimit := func(reason string) error {
		if policy.Limits.LimitBehavior == "error" {
			return harnessError("HARNESS_LIMIT_EXCEEDED")
		}
		s.Phase, s.Pending, s.ModelRequest = "done", nil, nil
		s.RepeatCountedCallID = ""
		s.Output = harnessLimitOutput(s.Output, reason)
		return saveTerminal()
	}
	returnLimitError := func() error {
		return harnessError("HARNESS_LIMIT_EXCEEDED")
	}
	unmarkUnsentRepeat := func(callID, digest string) {
		if s.RepeatCountedCallID == callID {
			s.RepeatCountedCallID = ""
			if s.ToolRepeats[digest] <= 1 {
				delete(s.ToolRepeats, digest)
			} else {
				s.ToolRepeats[digest]--
			}
		}
	}
	postHarness := func(path string, payload map[string]any) (map[string]any, error, bool, bool) {
		if path == "/internal/model/receipt" || path == "/internal/tool/receipt" {
			receiptCtx, receiptCancel := harnessReceiptContext(ctx)
			defer receiptCancel()
			result, err := port.Post(receiptCtx, path, payload)
			return result, err, false, true
		}
		requestCtx, requestCancel, allowed := harnessOperationContext(ctx, policy, s.LoopDeadlineMS)
		if !allowed {
			return nil, context.DeadlineExceeded, true, false
		}
		result, err := port.Post(requestCtx, path, payload)
		limited := harnessPolicyTimedOut(requestCtx, ctx, policy, s.LoopDeadlineMS)
		requestCancel()
		return result, err, limited, true
	}
	if legacyPolicyState && s.Phase != "model_dispatch" && s.Phase != "tool_dispatch" {
		if s.ToolRepeats == nil {
			s.ToolRepeats = map[string]int{}
		}
		if s.Phase == "approval_required" {
			if s.ToolCount != 0 || len(s.Pending) == 0 {
				return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
			}
			digest, err := harnessRepeatDigest(s.Pending[0].Name, s.Pending[0].Payload)
			if err != nil {
				return HarnessResult{}, err
			}
			s.ToolRepeats[digest] = 1
			s.RepeatCountedCallID = s.Pending[0].CallID
		}
		setCurrentPolicy()
		if err := save(); err != nil {
			return HarnessResult{}, err
		}
		legacyPolicyState = false
	}
	if len(skillRequests) > 0 && revision == 0 {
		if policy.remaining(s.LoopDeadlineMS) <= 0 {
			if err := finishForLimit("elapsed_limit"); err != nil {
				return HarnessResult{}, err
			}
		} else {
			stepCtx, stepCancel, allowed := harnessOperationContext(ctx, policy, s.LoopDeadlineMS)
			if !allowed {
				if err := finishForLimit("elapsed_limit"); err != nil {
					return HarnessResult{}, err
				}
			} else {
				bindings, message, err := resolveHarnessSkills(stepCtx, port, skillRequests, nil, true)
				limited := harnessPolicyTimedOut(stepCtx, ctx, policy, s.LoopDeadlineMS)
				stepCancel()
				if err != nil {
					if limited {
						if limitErr := finishForLimit("elapsed_limit"); limitErr != nil {
							return HarnessResult{}, limitErr
						}
					} else {
						return HarnessResult{}, err
					}
				} else {
					s.SkillBindings = bindings
					s.Messages = append(s.Messages, message)
				}
			}
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return HarnessResult{}, err
		}
		dispatchRecovering := s.Phase == "model_dispatch" || s.Phase == "tool_dispatch"
		if !dispatchRecovering && legacyPolicyState {
			setCurrentPolicy()
			legacyPolicyState = false
			if policy.remaining(s.LoopDeadlineMS) <= 0 {
				if err := finishForLimit("elapsed_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			} else if err := save(); err != nil {
				return HarnessResult{}, err
			}
		}
		if !dispatchRecovering && policy.remaining(s.LoopDeadlineMS) <= 0 {
			if err := finishForLimit("elapsed_limit"); err != nil {
				return HarnessResult{}, err
			}
			continue
		}
		stepCtx := ctx
		stepCancel := func() {}
		if !dispatchRecovering {
			var allowed bool
			stepCtx, stepCancel, allowed = harnessOperationContext(ctx, policy, s.LoopDeadlineMS)
			if !allowed {
				if err := finishForLimit("elapsed_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
		}
		if len(skillRequests) > 0 && !dispatchRecovering {
			if _, _, err := resolveHarnessSkills(stepCtx, port, skillRequests, s.SkillBindings, false); err != nil {
				limited := harnessPolicyTimedOut(stepCtx, ctx, policy, s.LoopDeadlineMS)
				stepCancel()
				if limited && !dispatchRecovering {
					if limitErr := finishForLimit("elapsed_limit"); limitErr != nil {
						return HarnessResult{}, limitErr
					}
					continue
				}
				return HarnessResult{}, err
			}
		}
		stepCancel()
		switch s.Phase {
		case "done":
			if completion, ok := port.(interface {
				CompleteRuntimeRecoveryStep(context.Context, string, string, string) error
			}); ok {
				if err := completion.CompleteRuntimeRecoveryStep(ctx, namespace, o.Key, stateSchema); err != nil {
					return HarnessResult{}, err
				}
			}
			if s.Output["completion_status"] == "incomplete" {
				return extendedHarnessResult(s, "incomplete", extended), nil
			}
			return extendedHarnessResult(s, "completed", extended), nil
		case "model", "model_dispatch":
			recovering := s.Phase == "model_dispatch"
			if revision >= 62 {
				return HarnessResult{}, harnessError("HARNESS_STATE_LIMIT")
			}
			if !recovering && s.Round >= effectiveMaxRounds {
				if err := finishForLimit("round_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			if !recovering {
				prepared, err, limited, _ := postHarness("/internal/context/prepare", map[string]any{"messages": s.Messages, "function_names": current["function_names"]})
				if err != nil {
					if limited {
						if limitErr := finishForLimit("elapsed_limit"); limitErr != nil {
							return HarnessResult{}, limitErr
						}
						continue
					}
					return HarnessResult{}, err
				}
				if policy.remaining(s.LoopDeadlineMS) <= 0 {
					if err := finishForLimit("elapsed_limit"); err != nil {
						return HarnessResult{}, err
					}
					continue
				}
				messages, valid := prepared["messages"].([]any)
				promptHash, _ := prepared["prompt_template_hash"].(string)
				sourceHash, _ := prepared["source_hash"].(string)
				if !valid || len(messages) == 0 || promptHash == "" || sourceHash == "" ||
					(promptHashProvided && (!requestedPromptHashIsString || requestedPromptHashText == "" || requestedPromptHashText != promptHash)) ||
					(s.PromptHash != "" && s.PromptHash != promptHash) {
					return HarnessResult{}, harnessError("HARNESS_CONTEXT_REJECTED")
				}
				s.PromptHash, s.ContextSourceHash = promptHash, sourceHash
				current["messages"], current["idempotency_key"] = messages, functionStepKey(key, s.Round, "model")
				current["prompt_template_hash"] = promptHash
				if extended {
					current["deadline_ms"] = s.LoopDeadlineMS
				}
				if len(s.SkillBindings) > 0 {
					current["skill_bindings"] = s.SkillBindings
				}
				s.ModelRequest, s.Phase = current, "model_dispatch"
				if err := save(); err != nil {
					return HarnessResult{}, err
				}
			}
			if s.ModelRequest == nil || s.ModelRequest["idempotency_key"] != functionStepKey(key, s.Round, "model") || s.PromptHash == "" || s.ModelRequest["prompt_template_hash"] != s.PromptHash {
				return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
			}
			path := "/internal/model/generate"
			if recovering {
				path = "/internal/model/receipt"
			}
			result, err, limited, attempted := postHarness(path, s.ModelRequest)
			if err != nil {
				if limited {
					if attempted {
						// The handler may have received the request. The next loop
						// iteration must resolve only the original receipt.
						continue
					}
					s.Phase, s.ModelRequest = "model", nil
					if policy.Limits.LimitBehavior == "error" {
						if err := saveTerminal(); err != nil {
							return HarnessResult{}, err
						}
						return HarnessResult{}, harnessError("HARNESS_LIMIT_EXCEEDED")
					}
					if err := finishForLimit("elapsed_limit"); err != nil {
						return HarnessResult{}, err
					}
					continue
				}
				if isHarnessBudgetDenial(err) {
					s.Phase, s.ModelRequest, s.Pending, s.Output = "done", nil, nil, harnessBudgetOutput(s.Output, "budget_exhausted")
					if err := save(); err != nil {
						return HarnessResult{}, err
					}
					continue
				}
				return HarnessResult{}, err
			}
			if recovering {
				if result["version"] != "model-receipt/v1" || result["idempotency_key"] != s.ModelRequest["idempotency_key"] {
					return HarnessResult{}, harnessError("MODEL_RECEIPT_REJECTED")
				}
				if result["status"] != "completed" {
					return HarnessResult{}, harnessError("HARNESS_RECONCILIATION_REQUIRED")
				}
				var valid bool
				result, valid = result["receipt"].(map[string]any)
				if !valid {
					return HarnessResult{}, harnessError("MODEL_RECEIPT_REJECTED")
				}
			}
			if legacyPolicyState {
				if s.ToolCount > 0 {
					return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
				}
				if err := refreshPolicyForLegacy(); err != nil {
					return HarnessResult{}, err
				}
				legacyPolicyState = false
			}
			if policyStateMismatch {
				return HarnessResult{}, policyValidationErr
			}
			if policy.remaining(s.LoopDeadlineMS) <= 0 {
				if policy.Limits.LimitBehavior == "error" {
					if recovering {
						s.Phase, s.ModelRequest = "model", nil
						s.Output = harnessLimitOutput(result, "elapsed_limit")
						if err := saveTerminal(); err != nil {
							return HarnessResult{}, err
						}
					}
					return HarnessResult{}, harnessError("HARNESS_LIMIT_EXCEEDED")
				}
				s.Phase, s.ModelRequest, s.Pending = "done", nil, nil
				s.RepeatCountedCallID = ""
				s.Output = harnessLimitOutput(result, "elapsed_limit")
				if err := saveTerminal(); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			if extended {
				receiptCopy, copyError := publicClone(result)
				if copyError != nil {
					return HarnessResult{}, copyError
				}
				s.ModelReceipts = append(s.ModelReceipts, map[string]any{"idempotency_key": s.ModelRequest["idempotency_key"], "receipt": receiptCopy})
			}
			s.ModelRequest = nil
			calls, _ := result["tool_calls"].([]any)
			exhausted, err := harnessBudgetExhausted(result)
			if err != nil {
				return HarnessResult{}, err
			}
			if exhausted && len(calls) > 0 {
				s.Phase, s.Pending, s.Output = "done", nil, harnessBudgetOutput(result, "budget_exhausted")
				if err := save(); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			if len(calls) == 0 || result["completion_status"] == "incomplete" {
				if result["completion_status"] == "tool_calls" {
					return HarnessResult{}, harnessError("FUNCTION_RESPONSE_INVALID")
				}
				s.Phase, s.Output = "done", result
				if err := save(); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			s.Output = harnessBudgetOutput(result, "tools_pending")
			if s.Round >= effectiveMaxRounds-1 {
				if err := finishForLimit("round_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			if len(calls)+s.ToolCount > effectiveMaxToolCalls {
				if err := finishForLimit("tool_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			bindings, _ := result["function_bindings"].(map[string]any)
			seen := map[string]bool{}
			for _, raw := range calls {
				call, _ := raw.(map[string]any)
				function, _ := call["function"].(map[string]any)
				name, _ := function["name"].(string)
				tool, _ := bindings[name].(string)
				id, _ := call["id"].(string)
				arguments, _ := function["arguments"].(string)
				var payload map[string]any
				dec := json.NewDecoder(bytes.NewBufferString(arguments))
				dec.UseNumber()
				if tool == "" || len(tool) > 128 || id == "" || len(id) > 128 || seen[id] || dec.Decode(&payload) != nil || payload == nil || dec.Decode(new(any)) != io.EOF {
					return HarnessResult{}, harnessError("FUNCTION_RESPONSE_INVALID")
				}
				seen[id] = true
				s.Pending = append(s.Pending, HarnessOperation{Name: tool, CallID: functionStepKey(key, s.Round, id), Payload: payload, ModelCallID: id})
			}
			if o.ActionValidator != nil {
				for _, operation := range s.Pending {
					candidate, _ := publicClone(map[string]any{"name": operation.Name, "call_id": operation.CallID, "payload": operation.Payload, "model_call_id": operation.ModelCallID})
					view, _ := publicClone(map[string]any{"round": s.Round, "tool_count": s.ToolCount, "observations": s.Observations})
					if !o.ActionValidator(candidate, view) {
						s.Phase, s.Pending, s.Output = "done", nil, harnessLimitOutput(result, "action_rejected")
						if err := saveTerminal(); err != nil {
							return HarnessResult{}, err
						}
						return HarnessResult{}, harnessError("HARNESS_ACTION_REJECTED")
					}
				}
			}
			s.Messages = append(s.Messages, map[string]any{"role": "assistant", "content": result["text"], "tool_calls": calls})
			s.Phase = "tool"
			if err := save(); err != nil {
				return HarnessResult{}, err
			}
		case "tool", "approval_required", "tool_dispatch":
			recovering := s.Phase == "tool_dispatch"
			if revision >= 62 {
				return HarnessResult{}, harnessError("HARNESS_STATE_LIMIT")
			}
			if len(s.Pending) == 0 {
				return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
			}
			operation := s.Pending[0]
			if !recovering && o.ActionValidator != nil {
				candidate, copyError := publicClone(map[string]any{"name": operation.Name, "call_id": operation.CallID, "payload": operation.Payload, "model_call_id": operation.ModelCallID})
				if copyError != nil {
					return HarnessResult{}, copyError
				}
				view, _ := publicClone(map[string]any{"round": s.Round, "tool_count": s.ToolCount, "observations": s.Observations})
				if !o.ActionValidator(candidate, view) {
					return HarnessResult{}, harnessError("HARNESS_ACTION_REJECTED")
				}
			}
			if s.Phase == "approval_required" && o.ConfirmationToken == "" {
				return HarnessResult{Status: "approval_required", Pending: &operation}, nil
			}
			repeatDigest, err := harnessRepeatDigest(operation.Name, operation.Payload)
			if err != nil {
				return HarnessResult{}, err
			}
			if !recovering {
				if s.RepeatCountedCallID != operation.CallID {
					nextCount := s.ToolRepeats[repeatDigest] + 1
					if nextCount > policy.Limits.MaxRepeatedCalls {
						if err := finishForLimit("repeated_tool_limit"); err != nil {
							return HarnessResult{}, err
						}
						continue
					}
					s.ToolRepeats[repeatDigest] = nextCount
					s.RepeatCountedCallID = operation.CallID
				}
				s.Phase = "tool_dispatch"
				if err := save(); err != nil {
					return HarnessResult{}, err
				}
			}
			command := map[string]any{"name": operation.Name, "call_id": operation.CallID, "payload": operation.Payload}
			if o.ConfirmationToken != "" {
				command["confirmation_token"] = o.ConfirmationToken
			}
			o.ConfirmationToken = ""
			path := "/internal/tool/invoke"
			if recovering {
				path = "/internal/tool/receipt"
			}
			receipt, err, limited, attempted := postHarness(path, command)
			if err != nil {
				var app *AppError
				confirmationRequired := errors.As(err, &app) && app.Code == "TOOL_CONFIRMATION_REQUIRED"
				if limited && attempted && !confirmationRequired {
					// Invocation may have reached the runtime; resolve only its receipt.
					continue
				}
				if limited && !attempted {
					s.Phase = "tool"
					unmarkUnsentRepeat(operation.CallID, repeatDigest)
					if policy.Limits.LimitBehavior == "error" {
						if err := saveTerminal(); err != nil {
							return HarnessResult{}, err
						}
						return HarnessResult{}, returnLimitError()
					}
					if err := finishForLimit("elapsed_limit"); err != nil {
						return HarnessResult{}, err
					}
					continue
				}
				if isHarnessBudgetDenial(err) {
					s.Phase, s.Pending, s.Output = "done", nil, harnessBudgetOutput(s.Output, "budget_exhausted")
					if err := save(); err != nil {
						return HarnessResult{}, err
					}
					continue
				}
				if confirmationRequired {
					if recovering {
						// An approval needed to read a committed receipt does not
						// prove the original dispatch was absent. Keep its durable
						// tool_dispatch phase so approval resumes receipt lookup,
						// never tool invocation or deadline-based abandonment.
						return HarnessResult{Status: "approval_required", Pending: &operation}, nil
					}
					s.Phase = "approval_required"
					if policy.remaining(s.LoopDeadlineMS) <= 0 {
						if policy.Limits.LimitBehavior == "error" {
							if err := saveTerminal(); err != nil {
								return HarnessResult{}, err
							}
							return HarnessResult{}, returnLimitError()
						}
						if err := finishForLimit("elapsed_limit"); err != nil {
							return HarnessResult{}, err
						}
						continue
					}
					if err := save(); err != nil {
						return HarnessResult{}, err
					}
					return HarnessResult{Status: "approval_required", Pending: &operation}, nil
				}
				return HarnessResult{}, err
			}
			if recovering {
				if receipt["version"] != "tool-receipt/v1" || receipt["tool_name"] != operation.Name || receipt["call_id"] != operation.CallID {
					return HarnessResult{}, harnessError("TOOL_RECEIPT_REJECTED")
				}
				if receipt["status"] != "completed" {
					return HarnessResult{}, harnessError("HARNESS_RECONCILIATION_REQUIRED")
				}
				var valid bool
				receipt, valid = receipt["receipt"].(map[string]any)
				if !valid {
					return HarnessResult{}, harnessError("TOOL_RECEIPT_REJECTED")
				}
			}
			if legacyPolicyState {
				if s.ToolCount > 0 {
					return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
				}
				if err := refreshPolicyForLegacy(); err != nil {
					return HarnessResult{}, err
				}
				legacyPolicyState = false
				s.ToolRepeats[repeatDigest] = 1
				s.RepeatCountedCallID = operation.CallID
			}
			if policyStateMismatch {
				return HarnessResult{}, policyValidationErr
			}
			if _, present := receipt["observation"]; !present {
				return HarnessResult{}, harnessError("TOOL_OBSERVATION_REJECTED")
			}
			value, err := functionToolContext(receipt, operation.Name, operation.CallID)
			if err != nil {
				return HarnessResult{}, err
			}
			body, err := json.Marshal(value)
			if err != nil {
				return HarnessResult{}, err
			}
			if extended {
				observation, copyError := publicClone(value)
				if copyError != nil {
					return HarnessResult{}, copyError
				}
				s.Observations = append(s.Observations, map[string]any{"operation": operation, "observation": observation})
			}
			s.Messages = append(s.Messages, map[string]any{"role": "tool", "tool_call_id": operation.ModelCallID, "content": string(body)})
			s.ToolCount++
			if s.RepeatCountedCallID == operation.CallID {
				s.RepeatCountedCallID = ""
			}
			s.Pending = s.Pending[1:]
			s.Phase = "tool"
			if len(s.Pending) == 0 {
				s.Round++
				s.Phase = "model"
			}
			if o.ProgressEvaluator != nil {
				observation, _ := publicClone(value)
				view, _ := publicClone(map[string]any{"round": s.Round, "tool_count": s.ToolCount, "observations": s.Observations})
				outcome, progressError := o.ProgressEvaluator(observation, view)
				if progressError != nil {
					return HarnessResult{}, progressError
				}
				if outcome != nil {
					if outcome["completion_status"] != "completed" && outcome["completion_status"] != "incomplete" {
						return HarnessResult{}, harnessError("HARNESS_PROGRESS_REJECTED")
					}
					s.Output, err = publicClone(outcome)
					if err != nil {
						return HarnessResult{}, err
					}
					s.Phase, s.Pending = "done", nil
				}
			}
			if policy.remaining(s.LoopDeadlineMS) <= 0 {
				if policy.Limits.LimitBehavior == "error" {
					if err := saveTerminal(); err != nil {
						return HarnessResult{}, err
					}
					return HarnessResult{}, returnLimitError()
				}
				if err := finishForLimit("elapsed_limit"); err != nil {
					return HarnessResult{}, err
				}
				continue
			}
			if err := save(); err != nil {
				return HarnessResult{}, err
			}
		default:
			return HarnessResult{}, harnessError("HARNESS_STATE_REJECTED")
		}
	}
}

func extendedHarnessResult(state harnessState, status string, extended bool) HarnessResult {
	result := HarnessResult{Status: status, Output: state.Output}
	if extended {
		result.Execution = map[string]any{"version": "harness-execution/v2", "extension_id": state.ExtensionID, "deadline_ms": state.LoopDeadlineMS, "decision_count": len(state.ModelReceipts), "tool_count": state.ToolCount, "model_receipts": state.ModelReceipts, "observations": state.Observations}
	}
	return result
}
