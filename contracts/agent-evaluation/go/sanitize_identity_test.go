package agenteval

import (
	"strings"
	"testing"
)

func TestSanitizePreservesIndexGenerationButRedactsActualKey(t *testing.T) {
	generation := "index-task-" + strings.Repeat("9e", 32)
	key := "sk-proj-" + strings.Repeat("x", 24)
	value := map[string]any{
		"kb_version": generation,
		"revision":   generation,
		"content":    "generation=" + generation + "; credential " + key,
		"api_key":    generation, // Sensitive field names always win.
	}
	clean := Sanitize(value).(map[string]any)
	if clean["kb_version"] != generation || clean["revision"] != generation {
		t.Fatal("public index generation was confused with an API key")
	}
	if clean["content"] != "generation="+generation+"; credential [REDACTED]" || clean["api_key"] != "[REDACTED]" {
		t.Fatal("actual secret or sensitive field escaped redaction")
	}
	if Sanitize(clean).(map[string]any)["content"] != clean["content"] {
		t.Fatal("redaction is not stable on repeated evaluation reads")
	}
}

func TestSanitizeKeyAtTextBoundariesAndChineseProse(t *testing.T) {
	key := "sk-" + strings.Repeat("x", 20)
	for _, text := range []string{key, "\"" + key + "\"", "密钥" + key, "key=" + key, "Bearer " + key} {
		if strings.Contains(Sanitize(text).(string), key) {
			t.Fatal("secret remained at a supported text boundary")
		}
	}
}
