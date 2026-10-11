package modelgateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
)

// This opt-in probe proves the guarded vendor wire protocol, not platform IAM
// or SQL settlement. Those are verified through the capability module tests.
func TestLiveDeepSeekNativeFunctionCalling(t *testing.T) {
	keyFile := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_DEEPSEEK_KEY_FILE"))
	if keyFile == "" {
		t.Skip("set LEXAGENT_LIVE_DEEPSEEK_KEY_FILE for the authorized live provider probe")
	}
	keyFile, err := filepath.Abs(keyFile)
	if err != nil {
		t.Fatal("invalid live provider key location")
	}
	model := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_DEEPSEEK_MODEL"))
	if model == "" {
		model = "deepseek-flash"
	}
	endpoint := strings.TrimSpace(os.Getenv("LEXAGENT_LIVE_DEEPSEEK_BASE_URL"))
	if endpoint == "" {
		endpoint = "https://api.deepseek.com"
	}
	catalog := testCatalog{provider: ProviderMetadata{ID: "live-provider", Key: "deepseek", TrustZone: trustExternal, EndpointRef: "ref://live", SecretRef: "secret://" + filepath.Base(keyFile), Status: approvedStatus}, model: ModelMetadata{ID: "live-model", VersionID: "live-v1", ProviderID: "live-provider", Key: model, Status: approvedStatus}}
	selection := Selection{ModelVersionID: "live-v1", ProviderID: "live-provider", ProviderKey: "deepseek", ModelID: "live-model", ModelKey: model, TrustZone: trustExternal}
	adapter, err := NewHTTPAdapter(HTTPConfig{SecretRoot: filepath.Dir(keyFile), RequestTimeout: 45 * time.Second, MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20}, testAccessResolver{selection: selection}, catalog, catalog, MountedSecretResolver{Root: filepath.Dir(keyFile)}, StaticEndpointResolver{"ref://live": endpoint})
	if err != nil {
		t.Fatal("guarded live function adapter unavailable")
	}
	policy := policyasset.ToolPolicy{AllowedTools: []string{"clock.now"}, Functions: []policyasset.FunctionDefinition{{Name: "read_clock", ToolName: "clock.now", Description: "Read the current UTC clock. Use this tool before answering any time question.", Parameters: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}}}
	snapshot := policyasset.Snapshot{Model: policyasset.ModelPolicy{Provider: "deepseek", Model: model, ModelVersionID: "live-v1", MaxTokens: 192, AllowExternal: true, ReasoningMode: "disabled"}, Tool: policy}
	request := GenerateRequest{Model: model, ModelVersionID: "live-v1", ProviderID: "live-provider", ModelID: "live-model", MaxTokens: 192, FunctionNames: []string{"read_clock"}, Messages: []Message{{Role: "user", Content: "Call read_clock with no arguments to obtain the current UTC time, then return only the UTC date in YYYY-MM-DD format. Do not guess the date."}}}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	first, err := adapter.Generate(ctx, trustedScope(), snapshot, request)
	if err != nil || first.Incomplete || len(first.ToolCalls) != 1 || first.ToolCalls[0].Function.Name != "read_clock" || first.InputTokens <= 0 || first.OutputTokens <= 0 {
		t.Fatalf("live native function call failed: error_type=%T calls=%d incomplete=%t input_tokens=%d output_tokens=%d", err, len(first.ToolCalls), first.Incomplete, first.InputTokens, first.OutputTokens)
	}
	date := time.Now().UTC().Format("2006-01-02")
	request.Messages = append(request.Messages, Message{Role: "assistant", Content: first.Text, ToolCalls: first.ToolCalls}, Message{Role: "tool", ToolCallID: first.ToolCalls[0].ID, Content: `{"utc":"` + date + `T00:00:00Z"}`})
	second, err := adapter.Generate(ctx, trustedScope(), snapshot, request)
	if err != nil || second.Incomplete || len(second.ToolCalls) != 0 || strings.TrimSpace(second.Text) != date || second.InputTokens <= 0 || second.OutputTokens <= 0 {
		t.Fatalf("live function result round trip failed: error_type=%T answer_matches=%t calls=%d incomplete=%t input_tokens=%d output_tokens=%d", err, strings.TrimSpace(second.Text) == date, len(second.ToolCalls), second.Incomplete, second.InputTokens, second.OutputTokens)
	}
	t.Logf("real native function round trip passed: first_input=%d first_output=%d second_input=%d second_output=%d", first.InputTokens, first.OutputTokens, second.InputTokens, second.OutputTokens)
}
