package policyasset

import (
	"context"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func validSnapshot() Snapshot {
	return Snapshot{ModelProfileID: "model-v1", PromptVersionID: "prompt-v1", ToolPolicyID: "tool-v1", MemoryPolicyID: "memory-v1", KnowledgePolicyID: "knowledge-v1", RuntimePolicyID: "runtime-v1", Revision: 1, Hash: "snapshot-hash"}
}

func TestStaticResolverReturnsCompleteSnapshot(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "p"}
	got, err := (StaticResolver{Snapshot: validSnapshot()}).Resolve(context.Background(), scope, "agent-version")
	if err != nil || got.Hash != "snapshot-hash" {
		t.Fatalf("unexpected policy snapshot: %+v, %v", got, err)
	}
}

func TestIncompleteSnapshotIsRejected(t *testing.T) {
	if err := (Snapshot{}).Validate(); err != ErrMissingPolicy {
		t.Fatalf("expected missing policy error, got %v", err)
	}
}

func TestExecutionInputMaterializesOnlyPublishedPolicyDetails(t *testing.T) {
	snapshot := Snapshot{
		ModelProfileID: "model-v1", PromptVersionID: "prompt-v1", ToolPolicyID: "tool-v1",
		MemoryPolicyID: "memory-v1", KnowledgePolicyID: "knowledge-v1", RuntimePolicyID: "runtime-v1",
		Revision: 3, Hash: strings.Repeat("a", 64),
		Model:     ModelPolicy{Provider: "local", Model: "test-model", MaxTokens: 512},
		Prompt:    PromptPolicy{TemplateHash: "prompt-hash", Template: "approved prompt"},
		Tool:      ToolPolicy{AllowedTools: []string{"json.validate"}},
		Memory:    MemoryPolicy{MaxEntries: 20},
		Knowledge: KnowledgePolicy{AllowedScopes: []string{"lexagent_local", "platform-knowledge"}, RequireReferences: true},
		Runtime:   RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 60},
	}
	input, err := snapshot.ExecutionInput()
	if err != nil {
		t.Fatal(err)
	}
	if input["content_hash"] != snapshot.Hash || input["revision"] != uint64(3) || input["knowledge_policy_id"] != "knowledge-v1" {
		t.Fatalf("immutable policy identity was not materialized: %#v", input)
	}
	if _, exists := input["provider_api_key"]; exists {
		t.Fatal("execution input must never contain provider credentials")
	}
	knowledge, ok := input["knowledge"].(KnowledgePolicy)
	if !ok || len(knowledge.AllowedScopes) != 2 || !knowledge.RequireReferences {
		t.Fatalf("materialized policy details are incomplete: %#v", input["knowledge"])
	}
}

func TestRuleBindingRequiresExactVersionAndChecksum(t *testing.T) {
	left := validSnapshot()
	left.Rule = RulePolicy{Version: "0.2.0", Checksum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	right := left
	if !left.SameRuleBinding(right) {
		t.Fatal("matching rule release should be authorized")
	}
	right.Rule.Checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if left.SameRuleBinding(right) {
		t.Fatal("different rule digest must be rejected")
	}
}

func TestRuleBindingPartialDetailsAreRejected(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Rule = RulePolicy{Version: "0.2.0"}
	if err := snapshot.ValidateDetails(); err != ErrMissingPolicy {
		t.Fatalf("expected partial rule binding to fail closed, got %v", err)
	}
}
