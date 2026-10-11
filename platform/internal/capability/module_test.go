package capability

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	modelgovernance "github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func capabilityContext() harnessContext {
	return harnessContext{
		TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app",
		AgentID: "document-assistant", AgentInstanceID: "instance-a", InstallationID: "install-a",
		AgentVersionID: "v1", PrincipalType: "user", ActorID: "user-a", RequestID: "request-a",
		TraceID: "0123456789abcdef0123456789abcdef", TaskID: "run-a", SessionID: "session-a",
		PlatformContextToken: "capability-token-a", ModelProfileID: "model-a", PromptVersionID: "prompt-a",
		MemoryPolicyID: "memory-a", ToolPolicyID: "tool-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		AuthorizationEpoch: 1,
	}
}

func capabilityRequest(t *testing.T, module *Module, path string, context harnessContext, input any) *httptest.ResponseRecorder {
	return capabilityRequestWithHeader(t, module, path, context, input, "Bearer "+context.PlatformContextToken)
}

func capabilityRequestWithHeader(t *testing.T, module *Module, path string, context harnessContext, input any, platformHeader string) *httptest.ResponseRecorder {
	t.Helper()
	if _, builtin := module.tools.(builtinToolProvider); builtin {
		if fields, ok := input.(map[string]any); ok && strings.HasPrefix(stringValue(fields["name"]), "fixture.") {
			module.SetToolProvider(fixtureToolProvider{})
		}
	}
	rawInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope{Context: context, Input: rawInput})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(module.signingSecret))
	_, _ = mac.Write(requestSignaturePayload(http.MethodPost, path, body))
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", module.internalToken)
	req.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	req.Header.Set("X-Platform-Context", platformHeader)
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, req)
	return response
}

func TestCapabilityGatewayRejectsMissingAndBadCredentials(t *testing.T) {
	module := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	req := httptest.NewRequest(http.MethodPost, "/internal/model/embed", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status=%d body=%s", response.Code, response.Body.String())
	}
	valid := capabilityRequest(t, module, "/internal/model/embed", capabilityContext(), map[string]any{"texts": []string{"abc"}})
	if valid.Code != http.StatusOK {
		t.Fatalf("valid request status=%d body=%s", valid.Code, valid.Body.String())
	}
	bad := capabilityContext()
	response = capabilityRequestWithHeader(t, module, "/internal/model/embed", bad, map[string]any{"texts": []string{"abc"}}, "Bearer other-token")
	if response.Code != http.StatusForbidden {
		t.Fatalf("context mismatch status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayEnforcesScopeAndPolicy(t *testing.T) {
	module := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	ctx := capabilityContext()
	ctx.PrincipalType = "user"
	response := capabilityRequest(t, module, "/internal/permission/check", ctx, map[string]any{"name": "fixture.read"})
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"allowed":true`)) {
		t.Fatalf("permission status=%d body=%s", response.Code, response.Body.String())
	}
	response = capabilityRequest(t, module, "/internal/permission/check", ctx, map[string]any{"name": "delete_everything"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied capability status=%d body=%s", response.Code, response.Body.String())
	}
	ctx.ApplicationID = ""
	response = capabilityRequest(t, module, "/internal/knowledge/search", ctx, map[string]any{"query": "文档"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("incomplete scope status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayServesModelKnowledgeAndToolContracts(t *testing.T) {
	module := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	ctx := capabilityContext()
	model := capabilityRequest(t, module, "/internal/model/generate", ctx, map[string]any{"messages": []map[string]string{{"role": "user", "content": "请诊断"}}})
	if model.Code != http.StatusOK || !bytes.Contains(model.Body.Bytes(), []byte(`"text"`)) {
		t.Fatalf("model status=%d body=%s", model.Code, model.Body.String())
	}
	knowledge := capabilityRequest(t, module, "/internal/knowledge/search", ctx, map[string]any{"query": "G01", "top_k": 1})
	if knowledge.Code != http.StatusOK || !bytes.Contains(knowledge.Body.Bytes(), []byte(`"retrieved_sources"`)) {
		t.Fatalf("knowledge status=%d body=%s", knowledge.Code, knowledge.Body.String())
	}
	tool := capabilityRequest(t, module, "/internal/tool/invoke", ctx, map[string]any{"name": "fixture.read", "call_id": "call-a", "payload": map[string]any{"batch_id": "demo-1104"}})
	if tool.Code != http.StatusOK || !bytes.Contains(tool.Body.Bytes(), []byte(`"status"`)) {
		t.Fatalf("tool status=%d body=%s", tool.Code, tool.Body.String())
	}

}

func TestToolInvocationIsIdempotentAndRejectsFingerprintReuse(t *testing.T) {
	module := newTestModule("internal-token", "signing-secret", nil, "platform", "agent-runtime")
	ctx := capabilityContext()
	input := map[string]any{
		"name":    "fixture.write",
		"call_id": "tool-call-1",
		"payload": map[string]any{"issue_id": "issue-a", "status": "open"},
	}
	first := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if first.Code != http.StatusOK {
		t.Fatalf("first tool call status=%d body=%s", first.Code, first.Body.String())
	}
	second := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if second.Code != http.StatusOK || second.Body.String() != first.Body.String() {
		t.Fatalf("tool replay should return identical response: first=%s second=%s", first.Body.String(), second.Body.String())
	}
	changed := map[string]any{
		"name":    "fixture.write",
		"call_id": "tool-call-1",
		"payload": map[string]any{"issue_id": "issue-b", "status": "open"},
	}
	conflict := capabilityRequest(t, module, "/internal/tool/invoke", ctx, changed)
	if conflict.Code != http.StatusConflict || !bytes.Contains(conflict.Body.Bytes(), []byte("TOOL_IDEMPOTENCY_CONFLICT")) {
		t.Fatalf("changed replay must be rejected: status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	other := ctx
	other.ActorID = "user-b"
	isolated := capabilityRequest(t, module, "/internal/tool/invoke", other, changed)
	if isolated.Code != http.StatusOK {
		t.Fatalf("same call ID in another scope must execute independently: status=%d body=%s", isolated.Code, isolated.Body.String())
	}
}

type fakeNotificationToolPort struct {
	calls     []NotificationToolCommand
	failCount int
}

func (p *fakeNotificationToolPort) Enqueue(_ context.Context, command NotificationToolCommand) (NotificationToolReceipt, error) {
	p.calls = append(p.calls, command)
	if p.failCount > 0 {
		p.failCount--
		return NotificationToolReceipt{}, ErrToolNotSubmitted
	}
	return NotificationToolReceipt{EventID: command.EventID, Status: "pending"}, nil
}

func notificationPolicyResolver() fixedPolicyResolver {
	return fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a",
		MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 1, Hash: "notification-policy-hash",
		Tool: policyasset.ToolPolicy{AllowedTools: []string{"send_notification"}},
	}}
}

func TestSendNotificationEnqueuesAndReplaysWithoutClaimingDelivery(t *testing.T) {
	resolver := notificationPolicyResolver()
	port := &fakeNotificationToolPort{failCount: 1}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, resolver)
	module.SetNotificationToolPort(port)
	ctx := capabilityContext()
	input := map[string]any{
		"name": "send_notification", "call_id": "notification-call-1",
		"payload": map[string]any{"receiver_id": "reviewer-1", "title": "审核完成", "text": "任务已完成审核"},
	}

	approveNotificationFixture(t, module, ctx, input)
	failed := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if failed.Code != http.StatusServiceUnavailable || !bytes.Contains(failed.Body.Bytes(), []byte("NOTIFICATION_ENQUEUE_FAILED")) {
		t.Fatalf("outbox failure must be explicit: status=%d body=%s", failed.Code, failed.Body.String())
	}
	if bytes.Contains(failed.Body.Bytes(), []byte(`"delivered":true`)) {
		t.Fatalf("failed enqueue must never claim delivery: %s", failed.Body.String())
	}

	first := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if first.Code != http.StatusOK || !bytes.Contains(first.Body.Bytes(), []byte(`"delivery_status":"pending"`)) || !bytes.Contains(first.Body.Bytes(), []byte(`"delivered":false`)) {
		t.Fatalf("successful enqueue must report accepted/pending, not delivered: status=%d body=%s", first.Code, first.Body.String())
	}
	second := capabilityRequest(t, module, "/internal/tool/invoke", ctx, input)
	if second.Code != http.StatusOK || second.Body.String() != first.Body.String() {
		t.Fatalf("completed tool call must replay the same receipt: first=%s second=%s", first.Body.String(), second.Body.String())
	}
	if len(port.calls) != 2 {
		t.Fatalf("expected one failed attempt and one retry, got %d calls", len(port.calls))
	}
	firstCommand, retryCommand := port.calls[0], port.calls[1]
	if firstCommand.EventID == "" || firstCommand.EventID != retryCommand.EventID || firstCommand.Scope.TenantID != ctx.TenantID || firstCommand.Scope.PrincipalID != ctx.ActorID || retryCommand.RecipientID != "reviewer-1" {
		t.Fatalf("notification retry must reuse a scoped stable event id: first=%+v retry=%+v", firstCommand, retryCommand)
	}
}

func TestSendNotificationFailsClosedWithoutOutbox(t *testing.T) {
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, notificationPolicyResolver())
	response := capabilityRequest(t, module, "/internal/tool/invoke", capabilityContext(), map[string]any{
		"name": "send_notification", "call_id": "notification-call-no-outbox",
		"payload": map[string]any{"receiver_id": "reviewer-1", "title": "审核完成", "text": "任务已完成审核"},
	})
	if response.Code != http.StatusServiceUnavailable || !bytes.Contains(response.Body.Bytes(), []byte("NOTIFICATION_UNAVAILABLE")) || bytes.Contains(response.Body.Bytes(), []byte(`"delivered":true`)) {
		t.Fatalf("missing Outbox must fail closed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func signedContextToken(t *testing.T, private ed25519.PrivateKey, context harnessContext, issuedAt, expiresAt int64) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := encode(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	claimValues := map[string]any{
		"iss": "platform", "aud": "agent-runtime", "subject_type": context.PrincipalType,
		"sub": context.ActorID, "tenant_id": context.TenantID, "application_id": context.ApplicationID,
		"agent_instance_id": context.AgentInstanceID, "iat": issuedAt, "exp": expiresAt,
		"department_id": context.DepartmentID, "installation_id": context.InstallationID, "agent_id": context.AgentID, "agent_version_id": context.AgentVersionID,
		"run_id": context.TaskID, "session_id": context.SessionID, "trace_id": context.TraceID, "authorization_epoch": context.AuthorizationEpoch,
		"actions": []string{"invoke"}, "body_hash": strings.Repeat("a", 64), "policy_snapshot_hash": strings.Repeat("b", 64),
		"execution_revision": 3, "lease_token_hash": strings.Repeat("c", 64),
	}
	if context.ParentRunID != "" {
		claimValues["parent_run_id"] = context.ParentRunID
	}
	claims := encode(claimValues)
	signingInput := header + "." + claims
	signature, err := private.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestCapabilityGatewayValidatesEd25519ExpiryAndInstance(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	module := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	module.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(context.Context, sharedkernel.Scope, string, string, string) error { return nil }))
	ctx := capabilityContext()
	now := time.Now().Unix()
	ctx.PlatformContextToken = signedContextToken(t, private, ctx, now-1, now+120)
	valid := capabilityRequest(t, module, "/internal/model/embed", ctx, map[string]any{"texts": []string{"abc"}})
	if valid.Code != http.StatusOK {
		t.Fatalf("valid Ed25519 status=%d body=%s", valid.Code, valid.Body.String())
	}
	expired := ctx
	expired.PlatformContextToken = signedContextToken(t, private, expired, now-120, now-60)
	response := capabilityRequest(t, module, "/internal/model/embed", expired, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired token status=%d body=%s", response.Code, response.Body.String())
	}
	otherInstance := ctx
	otherInstance.AgentInstanceID = "instance-b"
	response = capabilityRequest(t, module, "/internal/model/embed", otherInstance, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-instance status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayRejectsForgedEvaluationParentRun(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	module := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	var authorizedParent string
	module.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(_ context.Context, scope sharedkernel.Scope, _, _, _ string) error {
		authorizedParent = scope.ParentRunID
		return nil
	}))
	ctx := capabilityContext()
	ctx.ParentRunID = "evaluation-parent"
	now := time.Now().Unix()
	ctx.PlatformContextToken = signedContextToken(t, private, ctx, now-1, now+120)
	valid := capabilityRequest(t, module, "/internal/model/embed", ctx, map[string]any{"texts": []string{"abc"}})
	if valid.Code != http.StatusOK || authorizedParent != ctx.ParentRunID {
		t.Fatalf("signed parent not passed to live authority: status=%d parent=%q", valid.Code, authorizedParent)
	}
	forged := ctx
	forged.ParentRunID = "different-parent"
	response := capabilityRequest(t, module, "/internal/model/embed", forged, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusForbidden {
		t.Fatalf("forged parent status=%d body=%s", response.Code, response.Body.String())
	}
	forged.ParentRunID = ""
	response = capabilityRequest(t, module, "/internal/model/embed", forged, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusForbidden {
		t.Fatalf("omitted parent status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayBoundsRequestBody(t *testing.T) {
	module := newTestModule("internal-token", "", nil, "platform", "agent-runtime")
	body := bytes.Repeat([]byte("x"), maxBody+1)
	req := httptest.NewRequest(http.MethodPost, "/internal/model/embed", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", module.internalToken)
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status=%d body=%s", response.Code, response.Body.String())
	}
}

// 所有持久化身份维度都必须受签名绑定；each scope mutation is denied before capability execution.
func TestAuditCapabilityRejectsEveryScopeMutation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	module := newTestModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
	authorized := 0
	module.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(context.Context, sharedkernel.Scope, string, string, string) error {
		authorized++
		return nil
	}))
	original := capabilityContext()
	original.PlatformContextToken = signedContextToken(t, private, original, time.Now().Unix()-1, time.Now().Unix()+120)
	mutations := map[string]func(*harnessContext){
		"tenant":       func(c *harnessContext) { c.TenantID = "other" },
		"department":   func(c *harnessContext) { c.DepartmentID = "other" },
		"application":  func(c *harnessContext) { c.ApplicationID = "other" },
		"installation": func(c *harnessContext) { c.InstallationID = "other" },
		"instance":     func(c *harnessContext) { c.AgentInstanceID = "other" },
		"agent":        func(c *harnessContext) { c.AgentID = "other" },
		"version":      func(c *harnessContext) { c.AgentVersionID = "other" },
		"subject-type": func(c *harnessContext) { c.PrincipalType = "service_principal" },
		"subject-id":   func(c *harnessContext) { c.ActorID = "other" },
		"run":          func(c *harnessContext) { c.TaskID = "other" },
		"session":      func(c *harnessContext) { c.SessionID = "other" },
		"trace":        func(c *harnessContext) { c.TraceID = "other" },
		"epoch":        func(c *harnessContext) { c.AuthorizationEpoch++ },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			ctx := original
			change(&ctx)
			result := capabilityRequest(t, module, "/internal/model/embed", ctx, map[string]any{"texts": []string{"abc"}})
			if result.Code != http.StatusForbidden || authorized != 0 {
				t.Fatalf("scope drift admitted: %d", result.Code)
			}
		})
	}
	valid := capabilityRequest(t, module, "/internal/model/embed", original, map[string]any{"texts": []string{"abc"}})
	if valid.Code != http.StatusOK || authorized != 2 {
		t.Fatalf("legitimate signed scope was not authorized: status=%d calls=%d", valid.Code, authorized)
	}
}

type fixedPolicyResolver struct{ snapshot policyasset.Snapshot }

func (r fixedPolicyResolver) Resolve(_ context.Context, _ sharedkernel.Scope, _ string) (policyasset.Snapshot, error) {
	return r.snapshot, nil
}

func TestCapabilityGatewayEnforcesRuntimePolicySnapshot(t *testing.T) {
	resolver := fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a",
		MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 7, Hash: "snapshot-hash",
	}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, resolver)
	ctx := capabilityContext()
	response := capabilityRequest(t, module, "/internal/model/embed", ctx, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusOK {
		t.Fatalf("matching policy snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	for name, mutate := range map[string]func(*harnessContext){
		"model":     func(c *harnessContext) { c.ModelProfileID = "model-forged" },
		"prompt":    func(c *harnessContext) { c.PromptVersionID = "prompt-forged" },
		"tool":      func(c *harnessContext) { c.ToolPolicyID = "tool-forged" },
		"memory":    func(c *harnessContext) { c.MemoryPolicyID = "memory-forged" },
		"knowledge": func(c *harnessContext) { c.KnowledgePolicyID = "knowledge-forged" },
		"runtime":   func(c *harnessContext) { c.RuntimePolicyID = "runtime-forged" },
	} {
		t.Run(name, func(t *testing.T) {
			forged := capabilityContext()
			mutate(&forged)
			result := capabilityRequest(t, module, "/internal/model/embed", forged, map[string]any{"texts": []string{"abc"}})
			if result.Code != http.StatusForbidden {
				t.Fatalf("forged policy snapshot status=%d body=%s", result.Code, result.Body.String())
			}
		})
	}
	ctx = capabilityContext()
	ctx.RuntimePolicyID = ""
	response = capabilityRequest(t, module, "/internal/model/embed", ctx, map[string]any{"texts": []string{"abc"}})
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing policy snapshot status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayEnforcesPublishedToolAndKnowledgeDetails(t *testing.T) {
	resolver := fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a",
		MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 8, Hash: "snapshot-hash",
		Model:     policyasset.ModelPolicy{Provider: "local", Model: "fixture-local", MaxTokens: 64},
		Prompt:    policyasset.PromptPolicy{TemplateHash: "prompt-hash"},
		Tool:      policyasset.ToolPolicy{AllowedTools: []string{"fixture.read"}},
		Memory:    policyasset.MemoryPolicy{MaxEntries: 100},
		Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}, RequireReferences: true},
		Runtime:   policyasset.RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 60},
	}}
	provider := fakeKnowledgeProvider{result: map[string]any{"references": []map[string]any{{"doc_id": "d1"}}}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", provider, resolver)
	ctx := capabilityContext()
	deniedTool := capabilityRequest(t, module, "/internal/tool/invoke", ctx, map[string]any{"name": "send_notification", "call_id": "c1"})
	if deniedTool.Code != http.StatusForbidden {
		t.Fatalf("tool policy should deny unlisted tool: %d %s", deniedTool.Code, deniedTool.Body.String())
	}
	deniedKnowledge := capabilityRequest(t, module, "/internal/knowledge/search", ctx, map[string]any{"query": "G01", "knowledge_scope": "lexagent_local"})
	if deniedKnowledge.Code != http.StatusForbidden {
		t.Fatalf("knowledge policy should deny unlisted source: %d %s", deniedKnowledge.Code, deniedKnowledge.Body.String())
	}
	allowedKnowledge := capabilityRequest(t, module, "/internal/knowledge/search", ctx, map[string]any{"query": "G01", "knowledge_scope": "platform-knowledge"})
	if allowedKnowledge.Code != http.StatusOK {
		t.Fatalf("knowledge policy should allow listed source: %d %s", allowedKnowledge.Code, allowedKnowledge.Body.String())
	}
}

func governedModelResolver(provider string, allowExternal bool, budget int64) fixedPolicyResolver {
	return fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a",
		MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 10, Hash: "snapshot-hash",
		Model:     policyasset.ModelPolicy{Provider: provider, Model: "governed-model", MaxTokens: 2048, AllowExternal: allowExternal, BudgetCents: budget},
		Prompt:    policyasset.PromptPolicy{TemplateHash: "prompt-hash", Template: "受控模板"},
		Tool:      policyasset.ToolPolicy{AllowedTools: []string{"fixture.read"}},
		Memory:    policyasset.MemoryPolicy{WorkingTTLSeconds: 60, MaxEntries: 100},
		Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}},
		Runtime:   policyasset.RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 60},
	}}
}

func TestModelInvocationIsIdempotentAndRejectsFingerprintReuse(t *testing.T) {
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("local", false, 0))
	ctx := capabilityContext()
	input := map[string]any{"idempotency_key": "model-call-1", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "请诊断"}}}
	first := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if first.Code != http.StatusOK {
		t.Fatalf("first model call status=%d body=%s", first.Code, first.Body.String())
	}
	second := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if second.Code != http.StatusOK || second.Body.String() != first.Body.String() {
		t.Fatalf("replay should return identical response: first=%s second=%s", first.Body.String(), second.Body.String())
	}
	changed := map[string]any{"idempotency_key": "model-call-1", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "不同问题"}}}
	conflict := capabilityRequest(t, module, "/internal/model/generate", ctx, changed)
	if conflict.Code != http.StatusConflict || !bytes.Contains(conflict.Body.Bytes(), []byte("MODEL_IDEMPOTENCY_CONFLICT")) {
		t.Fatalf("changed replay must be rejected: status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestModelPolicyRejectsExternalProviderAndBudgetOverrun(t *testing.T) {
	external := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("openai", false, 0))
	input := map[string]any{"idempotency_key": "external-call", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "请诊断"}}}
	if response := capabilityRequest(t, external, "/internal/model/generate", capabilityContext(), input); response.Code != http.StatusForbidden {
		t.Fatalf("external model should be denied: %d %s", response.Code, response.Body.String())
	}
	budgeted := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("local", false, 1))
	first := capabilityRequest(t, budgeted, "/internal/model/generate", capabilityContext(), input)
	if first.Code != http.StatusOK {
		t.Fatalf("budgeted first call should fit: %d %s", first.Code, first.Body.String())
	}
	secondInput := map[string]any{"idempotency_key": "budget-call-2", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "第二次调用"}}}
	second := capabilityRequest(t, budgeted, "/internal/model/generate", capabilityContext(), secondInput)
	if second.Code != http.StatusPaymentRequired || !bytes.Contains(second.Body.Bytes(), []byte("MODEL_BUDGET_EXCEEDED")) {
		t.Fatalf("budget overrun should be denied: %d %s", second.Code, second.Body.String())
	}
}

func TestDevelopmentMockRemainsLocalAndRequiresExplicitEnvironment(t *testing.T) {
	input := map[string]any{"idempotency_key": "mock-development-call", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "请诊断"}}}
	for _, environment := range []string{"", "production", "development"} {
		module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("mock", false, 0))
		module.EnableDevelopmentMock(environment)
		response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
		if environment == "development" {
			if response.Code != http.StatusOK {
				t.Fatal("development mock treated as external", response.Code)
			}
		} else if response.Code != http.StatusForbidden || !bytes.Contains(response.Body.Bytes(), []byte("DEVELOPMENT_MODEL_DENIED")) {
			t.Fatal("mock escaped explicit development boundary", environment, response.Code)
		}
	}
}

type modelAccessResolverFunc func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error)

func (f modelAccessResolverFunc) ResolveModel(ctx context.Context, scope sharedkernel.Scope, versionID string) (modelgateway.Selection, error) {
	return f(ctx, scope, versionID)
}

type captureModelGateway struct {
	calls   int
	request modelgateway.GenerateRequest
	scope   sharedkernel.Scope
	result  modelgateway.GenerateResult
	err     error
	before  func()
}

func (g *captureModelGateway) Generate(_ context.Context, scope sharedkernel.Scope, _ policyasset.Snapshot, request modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.calls++
	g.scope, g.request = scope, request
	if g.before != nil {
		g.before()
	}
	return g.result, g.err
}
func (g *captureModelGateway) Embed(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) ([][]float32, error) {
	return nil, nil
}

func governedInvocationResolver() fixedPolicyResolver {
	resolver := governedModelResolver("provider-a", false, 0)
	resolver.snapshot.Model.Model = "chat-model-a"
	resolver.snapshot.Model.ModelVersionID = "version-a"
	return resolver
}

func TestCapabilityModelGenerationResolvesApprovedVersionBeforeGatewayAndReplays(t *testing.T) {
	accessCalls := 0
	access := modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, versionID string) (modelgateway.Selection, error) {
		accessCalls++
		if scope.TenantID != "tenant-a" || scope.ApplicationID != "business-app" || scope.PrincipalID != "user-a" || versionID != "version-a" {
			t.Fatalf("resolver received request-controlled scope or wrong catalog ID: scope=%+v version=%q", scope, versionID)
		}
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal, DeploymentID: "deployment-a", EndpointRef: "service://local-model", CapacityUnits: 4}, nil
	})
	prices := testApprovedPriceResolver()
	budgets := &captureModelBudgetStore{}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "governed answer", InputTokens: 12, OutputTokens: 4}}
	gateway.before = func() {
		if prices.calls != 1 || len(budgets.reserved) != 1 {
			t.Fatalf("price and budget reservation must precede provider call: price_calls=%d reservations=%d", prices.calls, len(budgets.reserved))
		}
	}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(access, gateway)
	module.SetModelBilling(prices, budgets)
	capacity := &captureModelCapacity{}
	module.SetModelCapacity(capacity)
	ctx := capabilityContext()
	input := map[string]any{"idempotency_key": "governed-call-a", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	first := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if first.Code != http.StatusOK || !bytes.Contains(first.Body.Bytes(), []byte("governed answer")) {
		t.Fatalf("governed call status=%d body=%s", first.Code, first.Body.String())
	}
	if gateway.calls != 1 || gateway.request.ModelVersionID != "version-a" || gateway.request.ProviderID != "provider-id-a" || gateway.request.ModelID != "model-id-a" || gateway.request.Model != "chat-model-a" {
		t.Fatalf("gateway did not receive the resolver's approved selection: calls=%d request=%+v", gateway.calls, gateway.request)
	}
	if gateway.scope.TenantID != "tenant-a" || gateway.scope.AgentVersionID != "v1" || gateway.scope.PrincipalID != "user-a" {
		t.Fatalf("gateway received wrong trusted scope: %+v", gateway.scope)
	}
	if len(budgets.settled) != 1 || budgets.settled[0].CostMicros != 2 || budgets.settled[0].InputTokens != 12 || budgets.settled[0].OutputTokens != 4 || budgets.settledPriceIDs[0] != "price-usd-v1" {
		t.Fatalf("actual provider usage was not settled at approved rates exactly once: events=%+v prices=%v", budgets.settled, budgets.settledPriceIDs)
	}
	second := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if second.Code != http.StatusOK || second.Body.String() != first.Body.String() || gateway.calls != 1 {
		t.Fatalf("idempotent replay called provider again: status=%d calls=%d body=%s", second.Code, gateway.calls, second.Body.String())
	}
	if accessCalls != 2 {
		t.Fatalf("authorization must run on each replay, calls=%d", accessCalls)
	}
}

func TestCapabilityModelGenerationFailsClosedOnPolicyMismatchAndAccessDenial(t *testing.T) {
	deniedGateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "must not run", InputTokens: 1, OutputTokens: 1}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
	}), deniedGateway)
	response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{"messages": []map[string]string{{"role": "user", "content": "x"}}})
	if response.Code != http.StatusForbidden || deniedGateway.calls != 0 {
		t.Fatalf("denied model access reached gateway: status=%d calls=%d body=%s", response.Code, deniedGateway.calls, response.Body.String())
	}

	module.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "p", ProviderKey: "different-provider", ModelID: "m", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal}, nil
	}), deniedGateway)
	response = capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{"messages": []map[string]string{{"role": "user", "content": "x"}}})
	if response.Code != http.StatusForbidden || deniedGateway.calls != 0 {
		t.Fatalf("catalog selection mismatch reached gateway: status=%d calls=%d body=%s", response.Code, deniedGateway.calls, response.Body.String())
	}
}

func TestCapabilityGovernedModelFailureCanRetryAfterFailureLedgerTransition(t *testing.T) {
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal, DeploymentID: "deployment-a", EndpointRef: "service://local-model", CapacityUnits: 4}, nil
	}), &captureModelGateway{err: modelgateway.ErrModelUnavailable})
	module.SetModelBilling(testApprovedPriceResolver(), &captureModelBudgetStore{})
	module.SetModelCapacity(&captureModelCapacity{})
	ctx := capabilityContext()
	input := map[string]any{"idempotency_key": "retry-after-provider-failure", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	response := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("provider failure status=%d body=%s", response.Code, response.Body.String())
	}
	module.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal, DeploymentID: "deployment-a", EndpointRef: "service://local-model", CapacityUnits: 4}, nil
	}), &captureModelGateway{result: modelgateway.GenerateResult{Text: "retry succeeded", InputTokens: 2, OutputTokens: 2}})
	module.SetModelCapacity(&captureModelCapacity{})
	response = capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("retry succeeded")) {
		t.Fatalf("failed idempotency entry did not retry: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPromptResolveUsesPublishedImmutableTemplate(t *testing.T) {
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedModelResolver("local", false, 0))
	response := capabilityRequest(t, module, "/internal/prompt/resolve", capabilityContext(), map[string]any{})
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"template":"受控模板"`)) {
		t.Fatalf("published prompt should be returned: %d %s", response.Code, response.Body.String())
	}
}

func TestCapabilityGatewayEnforcesScopedMemoryPolicy(t *testing.T) {
	resolver := fixedPolicyResolver{snapshot: policyasset.Snapshot{
		ModelProfileID: "model-a", PromptVersionID: "prompt-a", ToolPolicyID: "tool-a",
		MemoryPolicyID: "memory-a", KnowledgePolicyID: "knowledge-a", RuntimePolicyID: "runtime-a",
		Revision: 9, Hash: "snapshot-hash",
		Model:     policyasset.ModelPolicy{Provider: "local", Model: "fixture-local", MaxTokens: 64},
		Prompt:    policyasset.PromptPolicy{TemplateHash: "prompt-hash"},
		Tool:      policyasset.ToolPolicy{AllowedTools: []string{"fixture.read"}},
		Memory:    policyasset.MemoryPolicy{WorkingTTLSeconds: 30, MaxEntries: 1},
		Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"platform-knowledge"}, RequireReferences: true},
		Runtime:   policyasset.RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 60},
	}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, resolver)
	ctx := capabilityContext()
	saved := capabilityRequest(t, module, "/internal/memory/access", ctx, map[string]any{
		"operation": "save", "namespace": "qa", "key": "session-a", "value": map[string]any{"last_question": "G01"},
	})
	if saved.Code != http.StatusOK {
		t.Fatalf("memory save status=%d body=%s", saved.Code, saved.Body.String())
	}
	loaded := capabilityRequest(t, module, "/internal/memory/access", ctx, map[string]any{"operation": "load", "namespace": "qa", "key": "session-a"})
	if loaded.Code != http.StatusOK || !bytes.Contains(loaded.Body.Bytes(), []byte(`"last_question":"G01"`)) {
		t.Fatalf("memory load status=%d body=%s", loaded.Code, loaded.Body.String())
	}
	second := capabilityRequest(t, module, "/internal/memory/access", ctx, map[string]any{
		"operation": "save", "namespace": "qa", "key": "session-b", "value": map[string]any{"last_question": "G02"},
	})
	if second.Code != http.StatusConflict {
		t.Fatalf("memory max_entries status=%d body=%s", second.Code, second.Body.String())
	}
	other := ctx
	other.ActorID = "user-b"
	other.SessionID = "session-b"
	isolated := capabilityRequest(t, module, "/internal/memory/access", other, map[string]any{"operation": "load", "namespace": "qa", "key": "session-a"})
	if isolated.Code != http.StatusOK || !bytes.Contains(isolated.Body.Bytes(), []byte(`"value":null`)) {
		t.Fatalf("memory isolation status=%d body=%s", isolated.Code, isolated.Body.String())
	}
}

type fakeKnowledgeProvider struct{ result map[string]any }

func (p fakeKnowledgeProvider) Search(context.Context, harnessContext, knowledgeQuery) (map[string]any, error) {
	return p.result, nil
}
