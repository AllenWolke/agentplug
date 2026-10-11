package execution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestToolApprovalRunMetadataKeepsOwnerAndPolicyBoundary(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("approval-run").domain()
	module := NewModuleWithSharedRepository("test", store)
	policy := map[string]any{"content_hash": strings.Repeat("b", 64), "model_profile_id": "model", "prompt_version_id": "prompt", "tool_policy_id": "tools", "memory_policy_id": "memory", "knowledge_policy_id": "knowledge", "runtime_policy_id": "runtime", "prompt": "private-prompt-marker"}
	body, _ := json.Marshal(map[string]any{"input": map[string]any{"policy_snapshot": policy, "private_body": "private-input-marker"}, "context_token": "private-token-marker"})
	if _, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "approval", Fingerprint: "fp", RequestJSON: body}); err != nil {
		t.Fatal(err)
	}
	metadata, err := module.ResolveToolApprovalRun(context.Background(), scope, scope.RunID)
	if err != nil || metadata.Active {
		t.Fatal("accepted run marked active", err)
	}
	claimed, err := store.AcquireLease(scope.RunID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionLeased(scope.RunID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owner"); err != nil {
		t.Fatal(err)
	}
	metadata, err = module.ResolveToolApprovalRun(context.Background(), scope, scope.RunID)
	if err != nil || !metadata.Active || metadata.Scope != scope || metadata.PolicyIDs["tool_policy_id"] != "tools" || metadata.PolicyHash != strings.Repeat("b", 64) {
		t.Fatal("durable metadata mismatch", err)
	}
	raw, _ := json.Marshal(metadata)
	for _, marker := range []string{"private-prompt-marker", "private-input-marker", "private-token-marker"} {
		if strings.Contains(string(raw), marker) {
			t.Fatal("private Run material exposed")
		}
	}
	for _, change := range []func(*sharedkernel.Scope){func(s *sharedkernel.Scope) { s.PrincipalID = "foreign" }, func(s *sharedkernel.Scope) { s.TenantID = "foreign" }, func(s *sharedkernel.Scope) { s.ApplicationID = "foreign" }, func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" }} {
		actor := scope
		change(&actor)
		result, err := module.ResolveToolApprovalRun(context.Background(), actor, scope.RunID)
		if err == nil || result.PolicyHash != "" {
			t.Fatal("foreign actor read approval metadata")
		}
	}
}

func TestToolApprovalRunMetadataPreservesNestedRuleAndRejectsConflicts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		nested      any
		flatVersion string
		wantError   bool
	}{
		{"materialized", map[string]any{"version": "0.2.0", "checksum": strings.Repeat("a", 64)}, "", false},
		{"matching_legacy", map[string]any{"version": "0.2.0", "checksum": strings.Repeat("a", 64)}, "0.2.0", false},
		{"conflicting", map[string]any{"version": "0.2.0", "checksum": strings.Repeat("a", 64)}, "0.1.0", true},
		{"partial", map[string]any{"version": "0.2.0"}, "", true},
		{"wrong_type", "invalid", "", true},
		{"null", nil, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := platformruntime.NewStore()
			scope := testScope("approval-nested-" + tc.name).domain()
			module := NewModuleWithSharedRepository("test", store)
			policy := map[string]any{"content_hash": strings.Repeat("b", 64), "rule_bundle": tc.nested}
			if tc.flatVersion != "" {
				policy["rule_bundle_version"] = tc.flatVersion
			}
			body, _ := json.Marshal(map[string]any{"input": map[string]any{"policy_snapshot": policy}})
			if _, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "approval", Fingerprint: "fp", RequestJSON: body}); err != nil {
				t.Fatal(err)
			}
			metadata, err := module.ResolveToolApprovalRun(context.Background(), scope, scope.RunID)
			if tc.wantError {
				if err == nil {
					t.Fatal("invalid binding accepted")
				}
				return
			}
			if err != nil || metadata.PolicyIDs["rule_bundle_version"] != "0.2.0" || metadata.PolicyIDs["rule_bundle_checksum"] != strings.Repeat("a", 64) {
				t.Fatal("nested signed rule was lost", err)
			}
		})
	}
}
