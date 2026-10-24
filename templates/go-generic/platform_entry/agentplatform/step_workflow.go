package agentplatform

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const StepWorkflowSchema = "schema://agentplug/step-workflow/v1"
const stepWorkflowNamespace = "step-workflow"

type WorkflowStep struct {
	ID            string         `json:"id"`
	Payload       map[string]any `json:"payload"`
	DependsOn     []string       `json:"depends_on"`
	RequiredSlots []string       `json:"required_slots"`
}

type StepWorkflowOptions struct {
	Key                      string
	RequiredSlots            []string
	MaxSteps                 int
	MaxCalls                 map[string]int
	Timeout                  time.Duration
	DeadlineMS               int64
	AdditionalSteps          []WorkflowStep
	MaxExtensions            int
	PrepareOnly, InspectOnly bool
}

// StepExecutor must reconcile receipts in Recover, never resend an unknown
// provider operation. Only the gateway authorizes the actual model/tool send.
type StepExecutor interface {
	Execute(context.Context, WorkflowStep, *StepRuntime, map[string]any) (map[string]any, error)
	Recover(context.Context, WorkflowStep, *StepRuntime, map[string]any) (map[string]any, error)
}
type StepResultRevalidator interface {
	Revalidate(context.Context, WorkflowStep, map[string]any) (bool, error)
}

type StepRuntime struct {
	OperationKey string
	DeadlineMS   int64
	Recovering   bool
	remaining    func() time.Duration
	admit        func([]StepCall) error
}
type StepCall struct{ Kind, Key string }

func (r *StepRuntime) Remaining() (time.Duration, error) {
	v := r.remaining()
	if v <= 0 {
		return 0, publicError("STEP_DEADLINE_EXCEEDED")
	}
	return v, nil
}
func (r *StepRuntime) AdmitCall(kind, key string) error  { return r.admit([]StepCall{{kind, key}}) }
func (r *StepRuntime) AdmitCalls(calls []StepCall) error { return r.admit(calls) }

func DefaultStepWorkflowOptions(key string, slots []string) StepWorkflowOptions {
	return StepWorkflowOptions{Key: key, RequiredSlots: slots, MaxSteps: 6, MaxCalls: map[string]int{"model": 4, "knowledge": 4, "tool": 8}, Timeout: time.Minute, MaxExtensions: 1}
}

func normalizedSteps(steps []WorkflowStep, slots []string, maximum int, prior []WorkflowStep) ([]WorkflowStep, error) {
	if len(steps) < 1 || len(steps) > maximum {
		return nil, publicError("STEP_PLAN_REJECTED")
	}
	allowed := map[string]bool{}
	for _, slot := range slots {
		if requirePublicName(slot) != nil || allowed[slot] {
			return nil, publicError("STEP_CONFIG_INVALID")
		}
		allowed[slot] = true
	}
	seen := map[string]bool{}
	for _, step := range prior {
		seen[step.ID] = true
	}
	result := make([]WorkflowStep, 0, len(steps))
	for _, step := range steps {
		if requirePublicName(step.ID) != nil || seen[step.ID] || step.Payload == nil || len(step.DependsOn) > 32 || len(step.RequiredSlots) > 32 {
			return nil, publicError("STEP_PLAN_REJECTED")
		}
		deps := map[string]bool{}
		for _, id := range step.DependsOn {
			if !seen[id] || deps[id] {
				return nil, publicError("STEP_PLAN_REJECTED")
			}
			deps[id] = true
		}
		covered := map[string]bool{}
		for _, slot := range step.RequiredSlots {
			if !allowed[slot] || covered[slot] {
				return nil, publicError("STEP_PLAN_REJECTED")
			}
			covered[slot] = true
		}
		payload, err := publicClone(step.Payload)
		if err != nil {
			return nil, err
		}
		step.Payload = payload
		step.DependsOn = append([]string{}, step.DependsOn...)
		step.RequiredSlots = append([]string{}, step.RequiredSlots...)
		result = append(result, step)
		seen[step.ID] = true
	}
	return result, nil
}

func workflowResultValid(result map[string]any, step WorkflowStep) bool {
	if result == nil || (result["status"] != "completed" && result["status"] != "incomplete") {
		return false
	}
	if _, ok := result["output"].(map[string]any); !ok {
		return false
	}
	list, ok := result["covered_slots"].([]any)
	if !ok || len(list) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, raw := range list {
		slot, ok := raw.(string)
		if !ok || seen[slot] {
			return false
		}
		found := false
		for _, required := range step.RequiredSlots {
			found = found || required == slot
		}
		if !found {
			return false
		}
		seen[slot] = true
	}
	return result["status"] == "completed" || len(list) == 0
}

func (c *CapabilityClient) RunStepWorkflow(ctx context.Context, steps []WorkflowStep, executor StepExecutor, o StepWorkflowOptions) (map[string]any, error) {
	return RunStepWorkflow(ctx, c, steps, executor, o)
}

func RunStepWorkflow(ctx context.Context, port CapabilityPort, steps []WorkflowStep, executor StepExecutor, o StepWorkflowOptions) (map[string]any, error) {
	if ctx == nil || port == nil || executor == nil || requirePublicName(o.Key) != nil || len(o.RequiredSlots) < 1 || len(o.RequiredSlots) > 32 || o.MaxSteps < 1 || o.MaxSteps > 6 || o.MaxExtensions < 0 || o.MaxExtensions > 1 || o.Timeout <= 0 || o.Timeout > time.Hour || o.PrepareOnly && o.AdditionalSteps != nil || o.InspectOnly && (o.PrepareOnly || o.AdditionalSteps != nil) {
		return nil, publicError("STEP_CONFIG_INVALID")
	}
	initial, err := normalizedSteps(steps, o.RequiredSlots, o.MaxSteps, nil)
	if err != nil {
		return nil, err
	}
	limits := map[string]int{}
	if o.MaxCalls == nil {
		o.MaxCalls = map[string]int{"model": 4, "knowledge": 4, "tool": 8}
	}
	for kind, bound := range o.MaxCalls {
		if (kind != "model" && kind != "knowledge" && kind != "tool") || bound < 0 || bound > 16 {
			return nil, publicError("STEP_CONFIG_INVALID")
		}
		limits[kind] = bound
	}
	digest, err := publicDigest([]any{initial, o.RequiredSlots, o.MaxSteps, limits, o.MaxExtensions})
	if err != nil {
		return nil, err
	}
	entered := time.Now()
	policy, err := loadHarnessPublishedPolicy(ctx, port)
	if err != nil {
		return nil, err
	}
	deadline := policy.ServerTimeMS + min(o.Timeout.Milliseconds(), int64(policy.Limits.MaxElapsedSeconds)*1000)
	if o.DeadlineMS != 0 {
		if o.DeadlineMS < 1 || o.DeadlineMS > 1<<53-1 {
			return nil, publicError("STEP_CONFIG_INVALID")
		}
		deadline = min(deadline, o.DeadlineMS)
	}
	state := map[string]any{"version": "step-workflow/v1", "input_hash": digest, "phase": "running", "steps": initial, "required_slots": append([]string{}, o.RequiredSlots...), "results": map[string]any{}, "deadline_ms": deadline, "call_limits": limits, "reservations": map[string]any{}, "extensions": 0, "policy_hash": policy.Hash, "pending": nil}
	loaded, err := port.LoadCheckpoint(ctx, stepWorkflowNamespace, o.Key, StepWorkflowSchema, 0)
	if err != nil {
		return nil, err
	}
	if err = ValidateRuntimeRecoveryCheckpoint(ctx, stepWorkflowNamespace, o.Key, StepWorkflowSchema, loaded); err != nil {
		return nil, err
	}
	var revision uint64
	if loaded["checkpoint"] == nil {
		if o.InspectOnly {
			return nil, publicError("STEP_RECONCILIATION_REQUIRED")
		}
		if err = AuthorizeRuntimeRecoveryStart(ctx, stepWorkflowNamespace, o.Key, StepWorkflowSchema, digest); err != nil {
			return nil, err
		}
	} else {
		cp, ok := loaded["checkpoint"].(map[string]any)
		if !ok {
			return nil, publicError("STEP_STATE_REJECTED")
		}
		var valid bool
		revision, valid = handoffUint64(cp["revision"])
		previous, ok := cp["value"].(map[string]any)
		if !ok || !valid || revision < 1 || revision > 63 || previous["version"] != "step-workflow/v1" || previous["input_hash"] != digest {
			return nil, publicError("STEP_STATE_REJECTED")
		}
		state, err = publicClone(previous)
		if err != nil {
			return nil, err
		}
	}
	// Normalize JSON containers before either validation or persistence.
	state, err = publicClone(state)
	if err != nil {
		return nil, err
	}
	rawSteps, ok := state["steps"].([]any)
	if !ok {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	decodeSteps := func(raw []any) ([]WorkflowStep, error) {
		result := []WorkflowStep{}
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok || len(m) != 4 {
				return nil, publicError("STEP_STATE_REJECTED")
			}
			step := WorkflowStep{}
			step.ID, _ = m["id"].(string)
			step.Payload, _ = m["payload"].(map[string]any)
			for key, target := range map[string]*[]string{"depends_on": &step.DependsOn, "required_slots": &step.RequiredSlots} {
				v, ok := m[key].([]any)
				if !ok {
					return nil, publicError("STEP_STATE_REJECTED")
				}
				for _, item := range v {
					s, ok := item.(string)
					if !ok {
						return nil, publicError("STEP_STATE_REJECTED")
					}
					*target = append(*target, s)
				}
			}
			result = append(result, step)
		}
		return normalizedSteps(result, o.RequiredSlots, o.MaxSteps, nil)
	}
	currentSteps, err := decodeSteps(rawSteps)
	if err != nil {
		return nil, err
	}
	if len(currentSteps) < len(initial) {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	a, _ := publicDigest(currentSteps[:len(initial)])
	b, _ := publicDigest(initial)
	if a != b {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	for key, expected := range map[string]any{"required_slots": o.RequiredSlots, "call_limits": limits} {
		a, _ := publicDigest(state[key])
		b, _ := publicDigest(expected)
		if a != b {
			return nil, publicError("STEP_STATE_REJECTED")
		}
	}
	storedDeadline, valid := handoffUint64(state["deadline_ms"])
	extensions, ev := handoffUint64(state["extensions"])
	if !valid || storedDeadline == 0 || storedDeadline > uint64(deadline) || !ev || extensions > uint64(o.MaxExtensions) {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	results, ok := state["results"].(map[string]any)
	if !ok || len(results) > len(currentSteps) {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	reservations, ok := state["reservations"].(map[string]any)
	if !ok || len(reservations) > 32 {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	counts := func(values map[string]any) map[string]int {
		out := map[string]int{}
		for _, kind := range values {
			if s, ok := kind.(string); ok {
				out[s]++
			}
		}
		return out
	}
	for key, kind := range reservations {
		s, ok := kind.(string)
		bound, known := limits[s]
		if !ok || !known || requirePublicName(key) != nil || counts(reservations)[s] > bound {
			return nil, publicError("STEP_STATE_REJECTED")
		}
	}
	for _, step := range currentSteps[:len(results)] {
		result, ok := results[step.ID].(map[string]any)
		if !ok || !workflowResultValid(result, step) {
			return nil, publicError("STEP_STATE_REJECTED")
		}
		if check, ok := executor.(StepResultRevalidator); ok {
			copy, _ := publicClone(result)
			allowed, err := check.Revalidate(ctx, step, copy)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, publicError("STEP_RESULT_AUTHORITY_DENIED")
			}
		}
	}
	phase, _ := state["phase"].(string)
	if phase != "running" && phase != "dispatch" && phase != "awaiting_extension" && phase != "completed" && phase != "cancelled" && phase != "incomplete" {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	if phase == "dispatch" {
		if len(results) == len(currentSteps) || state["pending"] != currentSteps[len(results)].ID {
			return nil, publicError("STEP_STATE_REJECTED")
		}
	} else if state["pending"] != nil {
		return nil, publicError("STEP_STATE_REJECTED")
	}
	remaining := func() time.Duration {
		return time.Duration(int64(storedDeadline)-policy.ServerTimeMS)*time.Millisecond - time.Since(entered)
	}
	save := func() error {
		if revision >= 63 {
			return publicError("STEP_STATE_LIMIT")
		}
		copy, err := publicClone(state)
		if err != nil {
			return err
		}
		r, err := port.SaveCheckpoint(ctx, stepWorkflowNamespace, o.Key, StepWorkflowSchema, fmt.Sprintf("steps-%d", revision+1), revision, copy)
		if err != nil {
			return err
		}
		cp, ok := r["checkpoint"].(map[string]any)
		if !ok {
			return publicError("STEP_STATE_REJECTED")
		}
		next, ok := handoffUint64(cp["revision"])
		if !ok || next != revision+1 {
			return publicError("STEP_STATE_REJECTED")
		}
		revision++
		return nil
	}
	covered := func() map[string]bool {
		out := map[string]bool{}
		for _, raw := range results {
			r := raw.(map[string]any)
			for _, slot := range r["covered_slots"].([]any) {
				out[slot.(string)] = true
			}
		}
		return out
	}
	output := func() map[string]any {
		missing, complete := []string{}, []string{}
		slots := covered()
		for _, slot := range o.RequiredSlots {
			if slots[slot] {
				complete = append(complete, slot)
			} else {
				missing = append(missing, slot)
			}
		}
		status := "incomplete"
		if state["phase"] == "completed" {
			status = "completed"
		} else if state["phase"] == "cancelled" {
			status = "cancelled"
		}
		reason := state["finish_reason"]
		if reason == nil {
			reason = state["phase"]
		}
		calls := map[string]int{}
		for kind := range limits {
			calls[kind] = counts(reservations)[kind]
		}
		value, _ := publicClone(map[string]any{"status": status, "version": state["version"], "steps": currentSteps, "results": results, "missing_slots": missing, "covered_slots": complete, "deadline_ms": state["deadline_ms"], "extensions": state["extensions"], "calls": calls, "finish_reason": reason})
		return value
	}
	if o.InspectOnly {
		if state["policy_hash"] != policy.Hash {
			return nil, publicError("STEP_POLICY_REJECTED")
		}
		out := output()
		out["inspection"] = map[string]any{"read_only": true, "phase": phase, "pending_step": state["pending"], "reconciliation_required": phase == "dispatch", "expired": remaining() <= 0}
		return out, nil
	}
	if revision == 0 {
		if err = save(); err != nil {
			return nil, err
		}
	}
	if o.PrepareOnly {
		out := output()
		out["admission"] = map[string]any{"phase": state["phase"], "remaining_seconds": max(0, remaining().Seconds())}
		return out, nil
	}
	if o.AdditionalSteps != nil {
		appended, err := normalizedSteps(o.AdditionalSteps, o.RequiredSlots, o.MaxSteps-len(initial), initial)
		if err != nil {
			return nil, err
		}
		full := append(append([]WorkflowStep{}, initial...), appended...)
		if extensions > 0 {
			a, _ := publicDigest(full)
			b, _ := publicDigest(currentSteps)
			if a != b {
				return nil, publicError("STEP_EXTENSION_REJECTED")
			}
		} else {
			if phase != "awaiting_extension" || extensions >= uint64(o.MaxExtensions) {
				return nil, publicError("STEP_EXTENSION_REJECTED")
			}
			currentSteps = full
			state["steps"] = full
			state["phase"] = "running"
			state["extensions"] = 1
			if err = save(); err != nil {
				return nil, err
			}
		}
	}
	var reservationLock sync.Mutex
	admit := func(calls []StepCall) error {
		reservationLock.Lock()
		defer reservationLock.Unlock()
		if len(calls) < 1 || len(calls) > 32 {
			return publicError("STEP_CALL_REJECTED")
		}
		next, _ := publicClone(reservations)
		for _, call := range calls {
			bound, known := limits[call.Kind]
			if !known || requirePublicName(call.Key) != nil {
				return publicError("STEP_CALL_REJECTED")
			}
			if kind, exists := next[call.Key]; exists {
				if kind != call.Kind {
					return publicError("STEP_CALL_REJECTED")
				}
				continue
			}
			if len(next) >= 32 || counts(next)[call.Kind] >= bound {
				return publicError("STEP_CALL_LIMIT_EXCEEDED")
			}
			next[call.Key] = call.Kind
		}
		a, _ := publicDigest(next)
		b, _ := publicDigest(reservations)
		if a == b {
			return nil
		}
		if remaining() <= 0 {
			return publicError("STEP_DEADLINE_EXCEEDED")
		}
		old := reservations
		reservations = next
		state["reservations"] = next
		if err := save(); err != nil {
			reservations = old
			state["reservations"] = old
			return err
		}
		return nil
	}
	for {
		phase, _ = state["phase"].(string)
		if phase == "completed" || phase == "cancelled" || phase == "incomplete" || phase == "awaiting_extension" {
			if phase == "completed" {
				if len(results) != len(currentSteps) || len(covered()) != len(o.RequiredSlots) {
					return nil, publicError("STEP_STATE_REJECTED")
				}
				if client, ok := port.(interface {
					CompleteRuntimeRecoveryStep(context.Context, string, string, string) error
				}); ok {
					if err = client.CompleteRuntimeRecoveryStep(ctx, stepWorkflowNamespace, o.Key, StepWorkflowSchema); err != nil {
						return nil, err
					}
				}
			}
			return output(), nil
		}
		recovering := phase == "dispatch"
		if !recovering {
			if state["policy_hash"] != policy.Hash {
				return nil, publicError("STEP_POLICY_REJECTED")
			}
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			if remaining() <= 0 {
				state["phase"], state["finish_reason"] = "incomplete", "elapsed_limit"
				if err = save(); err != nil {
					return nil, err
				}
				return output(), nil
			}
		}
		if len(results) == len(currentSteps) {
			missing := len(o.RequiredSlots) - len(covered())
			state["phase"], state["finish_reason"] = "completed", "completed"
			if missing > 0 {
				state["phase"], state["finish_reason"] = "incomplete", "required_slots_missing"
				if extensions < uint64(o.MaxExtensions) {
					state["phase"] = "awaiting_extension"
				}
			}
			if err = save(); err != nil {
				return nil, err
			}
			continue
		}
		step := currentSteps[len(results)]
		for _, dependency := range step.DependsOn {
			r, ok := results[dependency].(map[string]any)
			if !ok || r["status"] != "completed" {
				state["phase"], state["pending"], state["finish_reason"] = "incomplete", nil, "dependency_incomplete"
				if err = save(); err != nil {
					return nil, err
				}
				return output(), nil
			}
		}
		key, err := publicDigest([]any{o.Key, digest, step})
		if err != nil {
			return nil, err
		}
		if !recovering {
			if client, ok := port.(interface{ ValidateCurrentExecution(context.Context) error }); ok {
				if err = client.ValidateCurrentExecution(ctx); err != nil {
					return nil, err
				}
			}
			state["phase"], state["pending"] = "dispatch", step.ID
			if err = save(); err != nil {
				return nil, err
			}
		}
		runtime := &StepRuntime{OperationKey: "step-" + key, DeadlineMS: int64(storedDeadline), Recovering: recovering, remaining: remaining, admit: admit}
		bound := remaining()
		if recovering {
			bound = min(o.Timeout, 5*time.Second)
		}
		if bound <= 0 {
			return nil, publicError("STEP_DEADLINE_EXCEEDED")
		}
		callCtx, cancel := context.WithTimeout(ctx, bound)
		prior, _ := publicClone(results)
		var result map[string]any
		if recovering {
			result, err = executor.Recover(callCtx, step, runtime, prior)
		} else {
			result, err = executor.Execute(callCtx, step, runtime, prior)
		}
		cancel()
		if err != nil {
			return nil, err
		}
		result, err = publicClone(result)
		if err != nil {
			return nil, err
		}
		if !workflowResultValid(result, step) {
			return nil, publicError("STEP_RECONCILIATION_REQUIRED")
		}
		results[step.ID] = result
		state["phase"], state["pending"] = "running", nil
		if len(results) == len(currentSteps) && state["policy_hash"] == policy.Hash {
			state["phase"], state["finish_reason"] = "completed", "completed"
			if len(covered()) != len(o.RequiredSlots) {
				state["phase"], state["finish_reason"] = "incomplete", "required_slots_missing"
				if extensions < uint64(o.MaxExtensions) {
					state["phase"] = "awaiting_extension"
				}
			}
			if remaining() <= 0 {
				state["phase"], state["finish_reason"] = "incomplete", "elapsed_limit"
			}
		}
		if err = save(); err != nil {
			return nil, err
		}
	}
}
