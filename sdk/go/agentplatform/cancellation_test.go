package agentplatform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCancellationRequiresPlatformCompletionEvidence(t *testing.T) {
	s, err := ReadCancellationState("cancelled", nil)
	if err != nil || s.Complete() || s.Disposition != "historical_unverified" {
		t.Fatal("bare stop became business cancellation")
	}
	p := map[string]any{"version": "cancellation-compensation/v1", "cancellation_id": strings.Repeat("a", 64), "phase": "complete", "stop_confirmed": true, "total": 2, "compensated": 1, "no_effect": 1, "unresolved": 0, "needs_attention": 0}
	v := map[string]any{"version": "cancellation-state/v1", "disposition": "verified", "progress": p}
	raw, _ := json.Marshal(v)
	s, err = ReadCancellationState("cancelled", raw)
	if err != nil || !s.Complete() {
		t.Fatal(err)
	}
	p["unresolved"] = 1
	p["no_effect"] = 0
	raw, _ = json.Marshal(v)
	if _, err = ReadCancellationState("cancelled", raw); err == nil {
		t.Fatal("pending effects accepted")
	}
	p["unresolved"] = 0
	p["no_effect"] = 1
	delete(p, "stop_confirmed")
	raw, _ = json.Marshal(v)
	if _, err = ReadCancellationState("cancelled", raw); err == nil {
		t.Fatal("missing stop accepted")
	}
}
