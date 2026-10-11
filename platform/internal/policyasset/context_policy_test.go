package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestContextPolicyBoundsAreValidatedBeforePublication(t *testing.T) {
	for _, raw := range []string{
		`{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":20,"cancel_grace_seconds":1}`,
		`{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":20,"cancel_grace_seconds":1,"context":{"max_messages":64,"mode":"window"}}`,
		`{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":20,"cancel_grace_seconds":1,"context":{"max_messages":64,"mode":"summary","summary_max_bytes":1024}}`,
	} {
		if err := validateAssetContent(AssetRuntime, json.RawMessage(raw)); err != nil {
			t.Fatalf("valid context rejected: %v", err)
		}
	}
	for _, raw := range []string{
		`{"max_messages":1,"mode":"window"}`,
		`{"max_messages":257,"mode":"window"}`,
		`{"max_messages":64,"mode":"arbitrary"}`,
		`{"max_messages":64,"mode":"summary","summary_max_bytes":127}`,
		`{"max_messages":64,"mode":"summary","summary_max_bytes":16385}`,
		`{"max_messages":64,"mode":"window","summary_max_bytes":128}`,
	} {
		asset := `{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":20,"cancel_grace_seconds":1,"context":` + raw + `}`
		if err := validateAssetContent(AssetRuntime, json.RawMessage(asset)); err == nil {
			t.Fatal("invalid context limits published")
		}
	}
	for _, limit := range []int{-1, 1048577} {
		value := ModelPolicy{Provider: "provider", Model: "model", MaxTokens: 256, MaxInputTokens: limit}
		raw, _ := json.Marshal(value)
		if err := validateAssetContent(AssetModel, raw); err == nil {
			t.Fatal("invalid model input limit published")
		}
	}
	legacy, _ := json.Marshal(RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 20})
	if strings.Contains(string(legacy), `"context"`) {
		t.Fatal("optional context changed legacy materialization")
	}
	legacyModel, _ := json.Marshal(ModelPolicy{MaxTokens: 256})
	if strings.Contains(string(legacyModel), `"max_input_tokens"`) {
		t.Fatal("optional input limit changed legacy materialization")
	}
}
