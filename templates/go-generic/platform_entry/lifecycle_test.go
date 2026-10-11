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

// newTemplateServer wires the template's own business seams behind the SDK
// transport with a freshly generated platform key.
// newTemplateServer 用新生成的平台密钥，把模板自身的业务接缝接入 SDK 传输层。
func newTemplateServer(t *testing.T) (*httptest.Server, *agentplatform.MemoryRunStore, ed25519.PrivateKey) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	store := agentplatform.NewMemoryRunStore()
	server, err := agentplatform.NewExecutionServer(agentplatform.ServerConfig{
		PublicKey: public, Issuer: "platform-runtime-gateway", Audience: defaultPlatformAudience,
		AgentID: defaultPlatformAudience, Capabilities: []string{"invoke", "run", "resume", "cancel", "events"},
		Store: store, Invoke: invokeBusiness, Run: runBusiness,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(server.Handler()), store, private
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

// TestTemplateServesTheLifecycleLegs proves the generated entry serves the
// optional lifecycle entries the platform conformance runner exercises:
// run → resume → events (SSE) → cancel, then invoke.
// TestTemplateServesTheLifecycleLegs 证明生成入口提供平台一致性 runner 驱动的可选
// 生命周期入口：run → resume → events（SSE）→ cancel，随后 invoke。
func TestTemplateServesTheLifecycleLegs(t *testing.T) {
	server, store, private := newTemplateServer(t)
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if record, ok := store.GetRun(runID); ok && record.Status == agentplatform.RunStatusSucceeded {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if record, ok := store.GetRun(runID); !ok || record.Status != agentplatform.RunStatusSucceeded {
		t.Fatalf("run never succeeded: %+v", record)
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
}

// TestTemplateRunHonorsCancellation proves the generated run seam observes the
// cancel channel end to end.
// TestTemplateRunHonorsCancellation 证明生成的 run 接缝端到端观察取消通道。
func TestTemplateRunHonorsCancellation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	store := agentplatform.NewMemoryRunStore()
	blocked := make(chan struct{})
	release := make(chan struct{})
	server, err := agentplatform.NewExecutionServer(agentplatform.ServerConfig{
		PublicKey: public, Issuer: "platform-runtime-gateway", Audience: defaultPlatformAudience,
		AgentID: defaultPlatformAudience, Capabilities: []string{"invoke", "run", "resume", "cancel", "events"},
		Store:  store,
		Invoke: invokeBusiness,
		Run: func(_ context.Context, _ agentplatform.ExecuteRequest, _ agentplatform.EventSink, cancelled <-chan struct{}) (map[string]any, error) {
			close(blocked)
			select {
			case <-cancelled:
				return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "run was cancelled", Retryable: false}
			case <-release:
				return map[string]any{"done": true}, nil
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	runID := "template-cancel-run"
	now := time.Now().UTC()
	run := templateRequest("run", runID, "idem-cancel-run")
	run.ContextToken = mintExecute(t, private, defaultPlatformAudience, "run", run, now)
	status, raw, _ := postJSON(t, httpServer.Client(), httpServer.URL+"/internal/agent-execution/v2/runs", run, run.ContextToken)
	if status != 202 {
		t.Fatalf("run leg: %d %s", status, raw)
	}
	<-blocked

	cancel := templateRequest("cancel", runID, "idem-cancel-run-cancel")
	cancel.ContextToken = mintExecute(t, private, defaultPlatformAudience, "cancel", cancel, now)
	status, raw, _ = postJSON(t, httpServer.Client(), httpServer.URL+"/internal/agent-execution/v2/runs/"+runID+"/cancel", cancel, cancel.ContextToken)
	if status != 202 {
		t.Fatalf("cancel leg: %d %s", status, raw)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if record, ok := store.GetRun(runID); ok && record.Status == agentplatform.RunStatusCancelled {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	record, _ := store.GetRun(runID)
	t.Fatalf("run was not cancelled: %+v", record)
}
