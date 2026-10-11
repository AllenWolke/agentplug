package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"generated-agent/platform_entry/agentplatform"
)

// mintToken mints gateway-shaped capabilities for template tests only;
// production tokens always come from the platform gateway.
// mintToken 仅为模板测试铸造网关形态的能力令牌；生产令牌一律来自平台网关。
func mintToken(t *testing.T, private ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(h+"."+p)))
}

func mintExecute(t *testing.T, private ed25519.PrivateKey, audience, action string, request agentplatform.ExecuteRequest, now time.Time) string {
	t.Helper()
	hash, err := agentplatform.CanonicalBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	snapshotHash := request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
	return mintToken(t, private, map[string]any{
		"iss": "platform-runtime-gateway", "aud": audience, "subject_type": request.Scope.PrincipalType, "sub": request.Scope.PrincipalID,
		"tenant_id": request.Scope.TenantID, "application_id": request.Scope.ApplicationID, "agent_instance_id": request.Scope.AgentInstanceID, "installation_id": request.Scope.InstallationID,
		"authorization_epoch": request.Scope.AuthorizationEpoch, "actions": []string{action},
		"policy_snapshot_hash": snapshotHash, "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
}

func mintEvent(t *testing.T, private ed25519.PrivateKey, audience string, request agentplatform.EventRequest, now time.Time) string {
	t.Helper()
	hash, err := agentplatform.CanonicalEventHash(request)
	if err != nil {
		t.Fatal(err)
	}
	return mintToken(t, private, map[string]any{
		"iss": "platform-runtime-gateway", "aud": audience, "subject_type": request.Scope.PrincipalType, "sub": request.Scope.PrincipalID,
		"tenant_id": request.Scope.TenantID, "application_id": request.Scope.ApplicationID, "agent_instance_id": request.Scope.AgentInstanceID, "installation_id": request.Scope.InstallationID,
		"authorization_epoch": request.Scope.AuthorizationEpoch, "actions": []string{"events"},
		"policy_snapshot_hash": request.PolicySnapshotHash, "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
}

// newTemplateServer wires the template's real Eino graph with a freshly
// generated platform key.
// newTemplateServer 用新生成的平台密钥接入模板真实的 Eino 图。
func newTemplateServer(t *testing.T) (*httptest.Server, *agentplatform.MemoryRunStore, ed25519.PrivateKey) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	graph, err := NewEchoGraph(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server, err := newExecutionServer(public, defaultPlatformAudience, agentplatform.NoopTracer(), graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(server.Handler()), nil, private
}

func templateRequest(operation, runID, idem string) agentplatform.ExecuteRequest {
	request := agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion, Operation: operation, IdempotencyKey: idem, InputSchema: "schema://agent/input/v1",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}, "task": "echo-" + runID},
		Scope: agentplatform.ScopeKey{AgentID: defaultPlatformAudience, TenantID: "tenant-a", AgentInstanceID: "instance-1", InstallationID: "installation-1", PrincipalType: "user", PrincipalID: "u1", RunID: runID, AuthorizationEpoch: 1},
	}
	if operation == "resume" {
		request.ResumeInput = map[string]any{"decision": "approve"}
	}
	return request
}

func postJSON(t *testing.T, client *http.Client, url string, payload any, token string) (int, string, string) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	return response.StatusCode, string(raw), response.Header.Get("Content-Type")
}

// TestTemplateServesTheLifecycleLegs proves the generated Eino entry serves the
// optional lifecycle entries the platform conformance runner exercises:
// run → resume → events (SSE) → cancel, then invoke.
// TestTemplateServesTheLifecycleLegs 证明生成的 Eino 入口提供平台一致性 runner 驱动
// 的可选生命周期入口：run → resume → events（SSE）→ cancel，随后 invoke。
func TestTemplateServesTheLifecycleLegs(t *testing.T) {
	server, _, private := newTemplateServer(t)
	defer server.Close()
	runID := "template-lifecycle-run"
	now := time.Now().UTC()

	run := templateRequest("run", runID, "idem-run")
	run.ContextToken = mintExecute(t, private, defaultPlatformAudience, "run", run, now)
	status, raw, contentType := postJSON(t, server.Client(), server.URL+"/internal/agent-execution/v2/runs", run, run.ContextToken)
	if status != 202 || !strings.Contains(contentType, "application/json") {
		t.Fatalf("run leg: %d %s %s", status, raw, contentType)
	}
	var accepted agentplatform.ExecuteResponse
	if err := json.Unmarshal([]byte(raw), &accepted); err != nil || accepted.RunID != runID || accepted.ProtocolVersion != agentplatform.ProtocolVersion {
		t.Fatalf("run leg response: %s (%v)", raw, err)
	}

	resume := templateRequest("resume", runID, "idem-resume")
	resume.ContextToken = mintExecute(t, private, defaultPlatformAudience, "resume", resume, now)
	status, raw, _ = postJSON(t, server.Client(), server.URL+"/internal/agent-execution/v2/runs/"+runID+"/resume", resume, resume.ContextToken)
	if status != 202 {
		t.Fatalf("resume leg: %d %s", status, raw)
	}

	events := agentplatform.EventRequest{ProtocolVersion: agentplatform.ProtocolVersion, Scope: run.Scope, AfterSeq: 0, PolicySnapshotHash: "snapshot-hash"}
	events.ContextToken = mintEvent(t, private, defaultPlatformAudience, events, now)
	status, raw, contentType = postJSON(t, server.Client(), server.URL+"/internal/agent-execution/v2/runs/"+runID+"/events", events, events.ContextToken)
	if status != 200 || !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("events leg: %d %s %s", status, raw, contentType)
	}
	frames := 0
	for _, block := range strings.Split(strings.TrimSpace(raw), "\n\n") {
		if block == "" {
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if index := strings.Index(line, ": "); index > 0 {
				fields[line[:index]] = line[index+2:]
			}
		}
		if fields["id"] == "" || fields["event"] == "" || fields["data"] == "" {
			t.Fatalf("partial SSE frame: %q", block)
		}
		var event agentplatform.ExecutionEvent
		if err := json.Unmarshal([]byte(fields["data"]), &event); err != nil {
			t.Fatalf("SSE data is not an execution event: %v", err)
		}
		if fmt.Sprintf("%d", event.Seq) != fields["id"] || event.RunID != runID {
			t.Fatalf("SSE frame mismatch: id=%s event=%+v", fields["id"], event)
		}
		frames++
	}
	if frames == 0 {
		t.Fatal("SSE replay contained no events")
	}

	cancel := templateRequest("cancel", runID, "idem-cancel")
	cancel.ContextToken = mintExecute(t, private, defaultPlatformAudience, "cancel", cancel, now)
	status, raw, _ = postJSON(t, server.Client(), server.URL+"/internal/agent-execution/v2/runs/"+runID+"/cancel", cancel, cancel.ContextToken)
	if status != 202 {
		t.Fatalf("cancel leg: %d %s", status, raw)
	}

	invoke := templateRequest("invoke", runID+"-invoke", "idem-invoke")
	invoke.ContextToken = mintExecute(t, private, defaultPlatformAudience, "invoke", invoke, now)
	status, raw, _ = postJSON(t, server.Client(), server.URL+"/internal/agent-execution/v2/invoke", invoke, invoke.ContextToken)
	if status != 200 {
		t.Fatalf("invoke leg: %d %s", status, raw)
	}
	var invoked agentplatform.ExecuteResponse
	if err := json.Unmarshal([]byte(raw), &invoked); err != nil {
		t.Fatal(err)
	}
	if invoked.Output["framework"] != "eino" || invoked.Output["run_id"] != invoke.Scope.RunID {
		t.Fatalf("the Eino graph output missed the platform context: %v", invoked.Output)
	}
}

// TestEinoGraphSeesTheVerifiedPlatformContext proves the bridge contract: the
// graph observes the run id and tenant of the VERIFIED scope, never a parsed
// token.
// TestEinoGraphSeesTheVerifiedPlatformContext 证明桥接契约：图读取的是已验证作用域
// 的 run id 与租户，绝不是自行解析的令牌。
func TestEinoGraphSeesTheVerifiedPlatformContext(t *testing.T) {
	graph, err := NewEchoGraph(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion, Operation: "invoke", IdempotencyKey: "bridge-check", InputSchema: "schema://agent/input/v1",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}, "task": "bridge"},
		Scope: agentplatform.ScopeKey{AgentID: defaultPlatformAudience, TenantID: "tenant-bridge", AgentInstanceID: "instance-1", InstallationID: "installation-1", PrincipalType: "user", PrincipalID: "u1", RunID: "bridge-run", AuthorizationEpoch: 1},
	}
	output, err := graph.Invoke(WithPlatformScope(context.Background(), request), request.Input)
	if err != nil {
		t.Fatal(err)
	}
	if output["framework"] != "eino" || output["run_id"] != "bridge-run" || output["tenant_id"] != "tenant-bridge" {
		t.Fatalf("the graph did not observe the verified platform context: %v", output)
	}
	// Without the bridge the platform context is absent, never guessed.
	// 未经桥接时平台上下文缺失，绝不臆造。
	plain, err := graph.Invoke(context.Background(), request.Input)
	if err != nil {
		t.Fatal(err)
	}
	if plain["run_id"] != "" || plain["tenant_id"] != "" {
		t.Fatalf("the graph invented platform context without the bridge: %v", plain)
	}
}
