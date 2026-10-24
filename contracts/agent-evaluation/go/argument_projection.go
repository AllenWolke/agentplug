package agenteval

import "strings"

const ToolArgumentProjectionV2 = "tool-arguments/v2"
const ScorerVersion = "agent-eval-rules/v2"

// UnknownArgumentEvidence distinguishes privacy/size markers from a measured
// wrong parameter. It never exposes the masked source or accepts it as correct.
func UnknownArgumentEvidence(v any) bool {
	nodes := 4096
	var unknown func(any, int) bool
	unknown = func(v any, depth int) bool {
		nodes--
		if nodes < 0 || depth >= 20 {
			return true
		}
		switch v := v.(type) {
		case string:
			return strings.Contains(v, "[REDACTED]") || strings.Contains(v, "[TRUNCATED]")
		case map[string]any:
			if marker, ok := v["_truncated"].(bool); ok && marker {
				return true
			}
			for _, item := range v {
				if unknown(item, depth+1) {
					return true
				}
			}
		case []any:
			for _, item := range v {
				if unknown(item, depth+1) {
					return true
				}
			}
		}
		return false
	}
	return unknown(v, 0)
}
