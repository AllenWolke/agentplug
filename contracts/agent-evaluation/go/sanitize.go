package agenteval

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var secretText = regexp.MustCompile(`(?i)(bearer\s+[a-z0-9._~+/=-]+|\bsk-[a-z0-9_-]{12,}|(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,;"']+)`)

// Sanitize is defense in depth, not a claim that arbitrary text contains no PII.
// Public reports never include raw outputs; protected trajectory output retains
// only bounded redacted values under existing history authorization.
func Sanitize(v any) any {
	nodes := 4096
	return sanitize(v, 0, &nodes)
}
func sanitize(v any, depth int, nodes *int) any {
	if depth >= 20 || *nodes <= 0 {
		return "[TRUNCATED]"
	}
	*nodes--
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		keys := []string{}
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 256 {
			// Reserve a slot for the marker so repeated redaction is stable.
			keys = keys[:255]
			out["_truncated"] = true
		}
		for _, k := range keys {
			value := x[k]
			lower := strings.ToLower(k)
			isCount := lower == "input_tokens" || lower == "output_tokens" || lower == "total_tokens"
			_, numeric := number(value)
			if (strings.Contains(lower, "token") && !(isCount && (numeric || value == nil))) || strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") || strings.Contains(lower, "credential") || lower == "environment" || lower == "env" || lower == "authorization" {
				out[k] = "[REDACTED]"
			} else {
				out[k] = sanitize(value, depth+1, nodes)
			}
		}
		return out
	case []any:
		if len(x) > 256 {
			x = x[:256]
		}
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = sanitize(value, depth+1, nodes)
		}
		return out
	case string:
		x = secretText.ReplaceAllString(x, "[REDACTED]")
		if len(x) > 8192 {
			n := 8192 - len("[TRUNCATED]")
			for n > 0 && !utf8.ValidString(x[:n]) {
				n--
			}
			x = x[:n] + "[TRUNCATED]"
		}
		return x
	default:
		return v
	}
}
