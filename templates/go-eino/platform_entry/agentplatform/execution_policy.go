package agentplatform

// ValidateExecutionPolicy validates the original batch window. A policy read
// cannot restart a task timeout or enlarge a published per-item budget.
func ValidateExecutionPolicy(r map[string]any) error {
	deny := func() error { return publicError("HARNESS_POLICY_REJECTED") }
	if len(r) != 5 || r["version"] != "harness-policy/v2" {
		return deny()
	}
	hash, ok := r["policy_hash"].(string)
	if !ok || !validHarnessPolicyHash(hash) {
		return deny()
	}
	now, valid := exactHarnessInteger(r["server_time_ms"])
	if !valid || now < 1 || now > 1<<53-1 {
		return deny()
	}
	limits, ok := r["limits"].(map[string]any)
	if _, valid := decodeHarnessLoopLimits(limits); !ok || !valid {
		return deny()
	}
	execution, ok := r["execution"].(map[string]any)
	if !ok || len(execution) < 2 || len(execution) > 3 {
		return deny()
	}
	for key := range execution {
		if key != "task_timeout_seconds" && key != "batch" && key != "window" {
			return deny()
		}
	}
	task, valid := exactHarnessInteger(execution["task_timeout_seconds"])
	if !valid || task < 1 {
		return deny()
	}
	raw, exists := execution["batch"]
	if !exists {
		return deny()
	}
	if raw == nil {
		if execution["window"] != nil {
			return deny()
		}
		return nil
	}
	batch, ok := raw.(map[string]any)
	if !ok || len(batch) != 3 {
		return deny()
	}
	items, a := exactHarnessInteger(batch["max_items"])
	item, b := exactHarnessInteger(batch["item_timeout_seconds"])
	elapsed, c := exactHarnessInteger(batch["elapsed_seconds"])
	if !a || !b || !c || items < 1 || items > 10000 || item < 1 || item > elapsed || elapsed > 3600 || elapsed != task {
		return deny()
	}
	window, ok := execution["window"].(map[string]any)
	if !ok || len(window) != 2 {
		return deny()
	}
	start, a := exactHarnessInteger(window["started_ms"])
	deadline, b := exactHarnessInteger(window["deadline_ms"])
	if !a || !b || start < 1 || start > now || deadline < 1 || deadline > 1<<53-1 || deadline != start+elapsed*1000 {
		return deny()
	}
	return nil
}
