package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestBillingDiagnosticsEscapeUntrustedTrace(t *testing.T) {
	var output bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()
	trace := "trace\r\nFORGED_LOG\x1b[31m"
	m := &Module{}
	if err := m.markModelReconciliation(context.Background(), "scope", "key", "fingerprint", usagecost.ModelBudgetReservation{}, nil, 0, trace, "attempt"); err == nil {
		t.Fatal("missing billing ports must still fail closed")
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || strings.ContainsAny(output.String(), "\r\x1b") {
		t.Fatalf("trace forged log lines: %q", output.String())
	}
	for _, line := range lines {
		if !strings.Contains(line, `trace="trace\r\nFORGED_LOG\x1b[31m"`) {
			t.Fatalf("trace is not escaped: %q", line)
		}
	}
}

func TestKnowledgeFailureLogDoesNotExposeProviderErrorOrForgeLines(t *testing.T) {
	var output bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()
	const private = "private-provider-body\r\nFORGED_LOG bearer-private-fixture"
	provider := knowledgeProviderFunc(func(context.Context, harnessContext, knowledgeQuery) (map[string]any, error) {
		return nil, errors.New(private)
	})
	policy := fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a", MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 1, Hash: "snapshot-hash", Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}},
	}}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", provider, policy)
	ctx := capabilityContext()
	ctx.TraceID = "trace\r\nFORGED_TRACE"
	w := capabilityRequest(t, m, "/internal/knowledge/search", ctx, map[string]any{"query": "example", "knowledge_scope": "platform-knowledge"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("knowledge failure status=%d body=%s", w.Code, w.Body.String())
	}
	line := strings.TrimSuffix(output.String(), "\n")
	if strings.ContainsAny(line, "\r\n") || strings.Contains(line, "private-provider-body") || strings.Contains(line, "bearer-private-fixture") || !strings.Contains(line, "error_type=") {
		t.Fatalf("unsafe knowledge failure log: %q", line)
	}
}

func TestRuntimeObservationJSONKeepsUntrustedMetadataOnOneLine(t *testing.T) {
	var output bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()
	trace := "trace\r\nFORGED_LOG\x1b[31m\u2028"
	logRuntimeObservation(runtimeObservation{TraceID: trace, RunID: trace, ToolName: trace})
	line := strings.TrimSuffix(output.String(), "\n")
	if strings.ContainsAny(line, "\r\n\x1b\u2028") {
		t.Fatalf("JSON observation forged a line: %q", line)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "runtime observation ")), &decoded); err != nil || decoded["trace_id"] != trace {
		t.Fatalf("metadata did not survive JSON escaping: err=%v data=%v", err, decoded)
	}
}
