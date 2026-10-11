package agentplatform

// HarnessPause parks a business handler without recording a failed outcome.
// Only non-secret operation identifiers are carried into lifecycle events;
// arguments remain in the governed run-scoped Harness checkpoint.
type HarnessPause struct {
	Key, ToolName, CallID string
}

func (p *HarnessPause) Error() string { return "harness requires governed human approval" }

func PauseHarness(result HarnessResult, key string) error {
	if result.Status != "approval_required" || result.Pending == nil || !agentGroupStateKey.MatchString(key) || !harnessSkillIdentifier(result.Pending.Name) || !harnessSkillIdentifier(result.Pending.CallID) {
		return harnessError("HARNESS_INCOMPLETE")
	}
	return &HarnessPause{Key: key, ToolName: result.Pending.Name, CallID: result.Pending.CallID}
}

func (p *HarnessPause) metadata() map[string]any {
	return map[string]any{"reason": "approval_required", "harness_key": p.Key, "tool_name": p.ToolName, "call_id": p.CallID}
}
