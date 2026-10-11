package agenteval

// ReviewEvidenceEvents keeps one verified terminal per tool invocation. Audit
// ordering must not let a later-listed executing record hide its outcome.
func ReviewEvidenceEvents(events []Event) []Event {
	result := observedToolCalls(events)
	for _, event := range events {
		if event.Kind != "tool" {
			result = append(result, event)
		}
	}
	return result
}

// Count one invocation across executing/terminal audit records. Run IDs keep
// sibling steps distinct. Missing stable identifiers are never guessed.
func observedToolCalls(events []Event) []Event {
	result := []Event{}
	positions := map[string]int{}
	terminal := func(e Event) bool {
		return e.FinishedAt != "" || e.Status == "succeeded" || e.Status == "ok" || e.Status == "failed" || e.Status == "cancelled" || e.Status == "denied"
	}
	for _, e := range events {
		if e.Kind != "tool" || e.ToolName == "" {
			continue
		}
		id := e.StepID
		if id == "" {
			id = e.CallID
		}
		key := e.RunID + "\x00" + e.ToolName + "\x00" + id
		if i, found := positions[key]; id != "" && found {
			old := result[i]
			if terminal(e) && !terminal(old) {
				if e.StartedAt == "" {
					e.StartedAt = old.StartedAt
				}
				result[i] = e
			} else if terminal(e) && terminal(old) && e.Status != old.Status {
				old.Status, old.ErrorType = "unknown", "CONFLICTING_TOOL_TERMINALS"
				result[i] = old
			}
			continue
		}
		if id != "" {
			positions[key] = len(result)
		}
		result = append(result, e)
	}
	return result
}
