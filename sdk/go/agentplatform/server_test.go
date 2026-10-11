package agentplatform

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
	"sync"
	"testing"
	"time"
)

// signToken mints gateway-shaped capabilities for tests only; production
// tokens always come from the platform gateway.
// signToken 仅为测试铸造网关形态的能力令牌；生产令牌一律来自平台网关。
func signToken(t *testing.T, private ed25519.PrivateKey, claims map[string]any) string {
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

func signExecute(t *testing.T, private ed25519.PrivateKey, issuer, audience, action string, request ExecuteRequest, now time.Time) string {
	t.Helper()
	hash, err := CanonicalBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	snapshotHash := request.Input["policy_snapshot"].(map[string]any)["content_hash"].(string)
	return signToken(t, private, map[string]any{
		"iss": issuer, "aud": audience, "subject_type": request.Scope.PrincipalType, "sub": request.Scope.PrincipalID,
		"tenant_id": request.Scope.TenantID, "application_id": request.Scope.ApplicationID, "agent_instance_id": request.Scope.AgentInstanceID, "installation_id": request.Scope.InstallationID,
		"authorization_epoch": request.Scope.AuthorizationEpoch, "actions": []string{action},
		"policy_snapshot_hash": snapshotHash, "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
}

func signEvent(t *testing.T, private ed25519.PrivateKey, issuer, audience string, request EventRequest, now time.Time) string {
	t.Helper()
	hash, err := CanonicalEventHash(request)
	if err != nil {
		t.Fatal(err)
	}
	return signToken(t, private, map[string]any{
		"iss": issuer, "aud": audience, "subject_type": request.Scope.PrincipalType, "sub": request.Scope.PrincipalID,
		"tenant_id": request.Scope.TenantID, "application_id": request.Scope.ApplicationID, "agent_instance_id": request.Scope.AgentInstanceID, "installation_id": request.Scope.InstallationID,
		"authorization_epoch": request.Scope.AuthorizationEpoch, "actions": []string{"events"},
		"policy_snapshot_hash": request.PolicySnapshotHash, "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
}

type fixtureKit struct {
	execution *ExecutionServer
	server    *httptest.Server
	store     *MemoryRunStore
	private   ed25519.PrivateKey
	now       time.Time
}

func newFixtureServer(t *testing.T, capabilities []string, run RunHandler) *fixtureKit {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryRunStore()
	cfg := ServerConfig{
		PublicKey: public, Issuer: "platform-runtime-gateway", Audience: "sdk-test-agent",
		AgentID: "sdk-test-agent", Capabilities: capabilities, Store: store,
		Invoke: func(_ context.Context, request ExecuteRequest) (map[string]any, error) {
			return map[string]any{"echo": request.Input}, nil
		},
	}
	if run == nil && contains(capabilities, "run") {
		run = func(_ context.Context, request ExecuteRequest, events EventSink, _ <-chan struct{}) (map[string]any, error) {
			_ = events.Append(EventProgress, map[string]any{"stage": "business"})
			return map[string]any{"echo": request.Input["business"]}, nil
		}
	}
	cfg.Run = run
	server, err := NewExecutionServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureKit{execution: server, server: httptest.NewServer(server.Handler()), store: store, private: private, now: time.Now().UTC()}
}

func (k *fixtureKit) executeRequest(t *testing.T, runID, operation, idem string) ExecuteRequest {
	t.Helper()
	request := ExecuteRequest{
		ProtocolVersion: ProtocolVersion, Operation: operation, IdempotencyKey: idem, InputSchema: "schema://t",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}, "business": "payload-" + runID},
		Scope: ScopeKey{AgentID: "sdk-test-agent", TenantID: "tenant-a", AgentInstanceID: "instance-1", InstallationID: "installation-1", PrincipalType: "user", PrincipalID: "u1", RunID: runID, AuthorizationEpoch: 1},
	}
	if operation == "resume" {
		request.ResumeInput = map[string]any{"decision": "approve"}
	}
	request.ContextToken = signExecute(t, k.private, "platform-runtime-gateway", "sdk-test-agent", operation, request, k.now)
	return request
}

// TestServerLifecycleLegsMatchConformance drives the exact legs the black-box
// conformance runner exercises: run → resume → events (SSE) → cancel.
// TestServerLifecycleLegsMatchConformance 按黑盒一致性 runner 的顺序驱动各 leg：
// run → resume → events（SSE）→ cancel。
func TestServerLifecycleLegsMatchConformance(t *testing.T) {
	kit := newFixtureServer(t, []string{"invoke", "run", "resume", "cancel", "events"}, nil)
	defer kit.server.Close()
	runID := "conformance-run"
	client := kit.server.Client()

	post := func(path string, payload any, token string) (int, string, string) {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, kit.server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		return response.StatusCode, string(raw), response.Header.Get("Content-Type")
	}

	run := kit.executeRequest(t, runID, "run", "conformance-run")
	status, raw, contentType := post("/internal/agent-execution/v2/runs", run, run.ContextToken)
	if status != 202 || !strings.Contains(contentType, "application/json") {
		t.Fatalf("run leg: %d %s %s", status, raw, contentType)
	}
	var accepted ExecuteResponse
	if err := json.Unmarshal([]byte(raw), &accepted); err != nil || accepted.RunID != runID || accepted.ProtocolVersion != ProtocolVersion {
		t.Fatalf("run leg response: %s (%v)", raw, err)
	}
	waitForStatus(t, kit.store, runID, RunStatusSucceeded)

	resume := kit.executeRequest(t, runID, "resume", "conformance-resume")
	status, raw, _ = post("/internal/agent-execution/v2/runs/"+runID+"/resume", resume, resume.ContextToken)
	if status != 202 {
		t.Fatalf("resume leg: %d %s", status, raw)
	}

	events := EventRequest{ProtocolVersion: ProtocolVersion, Scope: run.Scope, AfterSeq: 0, PolicySnapshotHash: "snapshot-hash"}
	events.ContextToken = signEvent(t, kit.private, "platform-runtime-gateway", "sdk-test-agent", events, kit.now)
	status, raw, contentType = post("/internal/agent-execution/v2/runs/"+runID+"/events", events, events.ContextToken)
	if status != 200 || !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("events leg: %d %s %s", status, raw, contentType)
	}
	assertSSEStream(t, raw, runID)

	cancel := kit.executeRequest(t, runID, "cancel", "conformance-cancel")
	status, raw, _ = post("/internal/agent-execution/v2/runs/"+runID+"/cancel", cancel, cancel.ContextToken)
	if status != 202 {
		t.Fatalf("cancel leg: %d %s", status, raw)
	}
	var cancelled ExecuteResponse
	if err := json.Unmarshal([]byte(raw), &cancelled); err != nil || cancelled.RunID != runID {
		t.Fatalf("cancel leg response: %s", raw)
	}

	invoke := kit.executeRequest(t, runID+"-invoke", "invoke", "conformance-invoke")
	status, raw, _ = post("/internal/agent-execution/v2/invoke", invoke, invoke.ContextToken)
	if status != 200 {
		t.Fatalf("invoke leg: %d %s", status, raw)
	}
}

func assertSSEStream(t *testing.T, raw string, runID string) {
	t.Helper()
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
		id := fields["id"]
		if id == "" || fields["event"] == "" || fields["data"] == "" {
			t.Fatalf("partial SSE frame: %q", block)
		}
		var event ExecutionEvent
		if err := json.Unmarshal([]byte(fields["data"]), &event); err != nil {
			t.Fatalf("SSE data is not an execution event: %v", err)
		}
		if fmt.Sprintf("%d", event.Seq) != id || event.RunID != runID {
			t.Fatalf("SSE frame mismatch: id=%s event=%+v", id, event)
		}
		frames++
	}
	if frames == 0 {
		t.Fatal("SSE replay contained no events")
	}
}

func waitForStatus(t *testing.T, store *MemoryRunStore, runID string, want RunStatus) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if record, ok := store.GetRun(runID); ok && record.Status == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	record, _ := store.GetRun(runID)
	t.Fatalf("run %s never reached %s (status %s)", runID, want, record.Status)
}

// TestServerConcurrentScopeIsolation drives parallel verified runs and proves
// outputs and events never cross run boundaries.
// TestServerConcurrentScopeIsolation 驱动并行已验证运行，证明输出与事件不会
// 跨运行边界泄漏。
func TestServerConcurrentScopeIsolation(t *testing.T) {
	kit := newFixtureServer(t, []string{"run", "resume", "cancel", "events"}, nil)
	defer kit.server.Close()
	client := kit.server.Client()
	const parallel = 12
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			runID := fmt.Sprintf("iso-run-%d", index)
			request := kit.executeRequest(t, runID, "run", "idem-"+runID)
			body, _ := json.Marshal(request)
			httpRequest, err := http.NewRequest(http.MethodPost, kit.server.URL+"/internal/agent-execution/v2/runs", bytes.NewReader(body))
			if err != nil {
				t.Error(err)
				return
			}
			httpRequest.Header.Set("Content-Type", "application/json")
			httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
			response, err := client.Do(httpRequest)
			if err != nil {
				t.Error(err)
				return
			}
			response.Body.Close()
			if response.StatusCode != 202 {
				t.Errorf("run %d rejected: %d", index, response.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < parallel; i++ {
		runID := fmt.Sprintf("iso-run-%d", i)
		waitForStatus(t, kit.store, runID, RunStatusSucceeded)
		record, ok := kit.store.GetRun(runID)
		if !ok {
			t.Fatalf("%s missing", runID)
		}
		want := fmt.Sprintf("payload-%s", runID)
		if got := record.Output["echo"]; got != want {
			t.Fatalf("%s output crossed scopes: %v", runID, got)
		}
		for _, event := range record.Events {
			if event.RunID != runID {
				t.Fatalf("%s observed a foreign event", runID)
			}
		}
	}
}

func TestServerContainsBusinessPanicsPerRun(t *testing.T) {
	const secretPanic = "PANIC_SECRET_MUST_NOT_LEAK"
	kit := newFixtureServer(t, []string{"invoke", "run", "resume", "cancel", "events"}, nil)
	defer kit.server.Close()
	kit.execution.cfg.Invoke = func(_ context.Context, request ExecuteRequest) (map[string]any, error) {
		if request.Scope.RunID == "panic-invoke" {
			panic(secretPanic)
		}
		return map[string]any{"healthy": request.Scope.RunID}, nil
	}
	unwound := make(chan struct{})
	kit.execution.cfg.Run = func(_ context.Context, request ExecuteRequest, _ EventSink, _ <-chan struct{}) (map[string]any, error) {
		if request.Scope.RunID == "panic-run" {
			defer close(unwound)
			panic(secretPanic)
		}
		return map[string]any{"healthy": request.Scope.RunID}, nil
	}
	post := func(path string, request ExecuteRequest) (int, string) {
		t.Helper()
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		httpRequest, err := http.NewRequest(http.MethodPost, kit.server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
		response, err := kit.server.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return response.StatusCode, string(raw)
	}
	assertSanitizedFailure := func(runID, raw string) {
		t.Helper()
		if strings.Contains(raw, secretPanic) {
			t.Fatalf("panic value leaked in response: %s", raw)
		}
		var response ExecuteResponse
		if err := json.Unmarshal([]byte(raw), &response); err != nil {
			t.Fatalf("invalid panic response %q: %v", raw, err)
		}
		if response.RunID != runID || response.Status != "failed" || response.Error == nil || response.Error.Code != "INTERNAL" ||
			response.Error.Message != "the agent failed to process the request" || len(response.Output) != 0 {
			t.Fatalf("unexpected sanitized panic response: %+v", response)
		}
	}
	assertStoredFailure := func(runID string) {
		t.Helper()
		record, ok := kit.store.GetRun(runID)
		if !ok || record.Status != RunStatusFailed || record.Error == nil || record.Error.Code != "INTERNAL" || len(record.Output) != 0 {
			t.Fatalf("panic run terminal record is unsafe: %+v", record)
		}
		encoded, _ := json.Marshal(record)
		if bytes.Contains(encoded, []byte(secretPanic)) {
			t.Fatalf("panic value leaked into stored run: %s", encoded)
		}
	}

	panicRun := kit.executeRequest(t, "panic-run", "run", "idem-panic-run")
	status, raw := post("/internal/agent-execution/v2/runs", panicRun)
	if status != http.StatusAccepted {
		t.Fatalf("panic run admission failed: %d %s", status, raw)
	}
	waitForStatus(t, kit.store, "panic-run", RunStatusFailed)
	select {
	case <-unwound:
	case <-time.After(time.Second):
		t.Fatal("business handler did not unwind after panic")
	}
	kit.execution.activeMu.Lock()
	active := kit.execution.active["panic-run"]
	kit.execution.activeMu.Unlock()
	if active == nil {
		t.Fatal("panicking run lost its active execution record")
	}
	select {
	case <-active.done:
	case <-time.After(time.Second):
		t.Fatal("panic run released no handler-exit proof")
	}
	assertStoredFailure("panic-run")

	panicInvoke := kit.executeRequest(t, "panic-invoke", "invoke", "idem-panic-invoke")
	status, raw = post("/internal/agent-execution/v2/invoke", panicInvoke)
	if status != http.StatusInternalServerError {
		t.Fatalf("invoke panic returned %d: %s", status, raw)
	}
	assertSanitizedFailure("panic-invoke", raw)
	assertStoredFailure("panic-invoke")

	healthyRun := kit.executeRequest(t, "healthy-run", "run", "idem-healthy-run")
	status, raw = post("/internal/agent-execution/v2/runs", healthyRun)
	if status != http.StatusAccepted {
		t.Fatalf("service rejected a healthy run after panic: %d %s", status, raw)
	}
	waitForStatus(t, kit.store, "healthy-run", RunStatusSucceeded)
	if record, ok := kit.store.GetRun("healthy-run"); !ok || record.Output["healthy"] != "healthy-run" {
		t.Fatalf("healthy run did not complete after panic: %+v", record)
	}

	healthyInvoke := kit.executeRequest(t, "healthy-invoke", "invoke", "idem-healthy-invoke")
	status, raw = post("/internal/agent-execution/v2/invoke", healthyInvoke)
	if status != http.StatusOK || !strings.Contains(raw, "healthy-invoke") || strings.Contains(raw, secretPanic) {
		t.Fatalf("service rejected a healthy invocation after panic: %d %s", status, raw)
	}
}

// TestServerCancelNotifiesTheBusinessHandler proves cooperative cancellation
// end to end: cancel closes the channel the handler observes.
// TestServerCancelNotifiesTheBusinessHandler 证明端到端协作式取消：cancel 关闭
// 业务处理器观察的通道。
func TestServerCancelNotifiesTheBusinessHandler(t *testing.T) {
	started := make(chan struct{})
	released := make(chan struct{})
	kit := newFixtureServer(t, []string{"run", "resume", "cancel", "events"}, func(_ context.Context, _ ExecuteRequest, _ EventSink, cancelled <-chan struct{}) (map[string]any, error) {
		close(started)
		select {
		case <-cancelled:
			return nil, &AppError{Code: "CANCELLED", Message: "run was cancelled", Retryable: false}
		case <-released:
			return map[string]any{"done": true}, nil
		}
	})
	defer kit.server.Close()
	runID := "cancel-notify-run"
	request := kit.executeRequest(t, runID, "run", "idem-cancel-notify")
	body, _ := json.Marshal(request)
	httpRequest, _ := http.NewRequest(http.MethodPost, kit.server.URL+"/internal/agent-execution/v2/runs", bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
	response, err := kit.server.Client().Do(httpRequest)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	<-started

	cancelRequest := kit.executeRequest(t, runID, "cancel", "idem-cancel-notify-cancel")
	cancelBody, _ := json.Marshal(cancelRequest)
	cancelHTTP, _ := http.NewRequest(http.MethodPost, kit.server.URL+"/internal/agent-execution/v2/runs/"+runID+"/cancel", bytes.NewReader(cancelBody))
	cancelHTTP.Header.Set("Content-Type", "application/json")
	cancelHTTP.Header.Set("Authorization", "Bearer "+cancelRequest.ContextToken)
	cancelResponse, err := kit.server.Client().Do(cancelHTTP)
	if err != nil {
		t.Fatal(err)
	}
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != 202 {
		t.Fatalf("cancel leg: %d", cancelResponse.StatusCode)
	}
	waitForStatus(t, kit.store, runID, RunStatusCancelled)
	select {
	case <-released:
	default:
		close(released)
	}
}

// TestServerFailClosedLadder covers the fail-closed transport checks: bearer
// binding, tampering, malformed envelopes, path binding and capability
// advertisement.
// TestServerFailClosedLadder 覆盖失败闭合的传输检查：Bearer 绑定、篡改、畸形信封、
// 路径绑定与能力宣告。
func TestServerFailClosedLadder(t *testing.T) {
	kit := newFixtureServer(t, []string{"invoke"}, nil)
	defer kit.server.Close()
	client := kit.server.Client()
	postRaw := func(path string, raw []byte, token string) int {
		request, err := http.NewRequest(http.MethodPost, kit.server.URL+path, bytes.NewReader(raw))
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
		response.Body.Close()
		return response.StatusCode
	}
	invoke := kit.executeRequest(t, "ladder-run", "invoke", "ladder-idem")
	body, _ := json.Marshal(invoke)
	if code := postRaw("/internal/agent-execution/v2/invoke", body, invoke.ContextToken); code != 200 {
		t.Fatalf("verified invoke rejected: %d", code)
	}
	if code := postRaw("/internal/agent-execution/v2/invoke", body, ""); code != 401 {
		t.Fatalf("missing bearer: %d", code)
	}
	if code := postRaw("/internal/agent-execution/v2/invoke", append(body, '}'), invoke.ContextToken); code != 400 {
		t.Fatalf("malformed envelope: %d", code)
	}
	tampered := kit.executeRequest(t, "ladder-run", "invoke", "ladder-idem")
	tampered.Input["injected"] = "value"
	tamperedBody, _ := json.Marshal(tampered)
	if code := postRaw("/internal/agent-execution/v2/invoke", tamperedBody, tampered.ContextToken); code != 401 {
		t.Fatalf("tampered body: %d", code)
	}
	// run is not advertised on this server; the entry must fail closed.
	if code := postRaw("/internal/agent-execution/v2/runs", body, invoke.ContextToken); code != 404 {
		t.Fatalf("unadvertised capability: %d", code)
	}
	// resume path binding: path run id must match the verified scope.
	resume := kit.executeRequest(t, "ladder-run", "resume", "ladder-resume")
	resumeBody, _ := json.Marshal(resume)
	if code := postRaw("/internal/agent-execution/v2/runs/other-run/resume", resumeBody, resume.ContextToken); code != 404 {
		t.Fatalf("unadvertised resume: %d", code)
	}
}

func TestServerConfigurationFailsClosed(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewExecutionServer(ServerConfig{Issuer: "i", Audience: "a", AgentID: "g", Store: NewMemoryRunStore(), Invoke: func(context.Context, ExecuteRequest) (map[string]any, error) { return nil, nil }}); err == nil {
		t.Fatal("server built without a public key")
	}
	if _, err := NewExecutionServer(ServerConfig{PublicKey: public, Issuer: "i", Audience: "a", AgentID: "g", Invoke: func(context.Context, ExecuteRequest) (map[string]any, error) { return nil, nil }}); err == nil {
		t.Fatal("server built without a run store")
	}
	if _, err := NewExecutionServer(ServerConfig{PublicKey: public, Issuer: "i", Audience: "a", AgentID: "g", Store: NewMemoryRunStore()}); err == nil {
		t.Fatal("invoke advertised without a handler")
	}
	if _, err := NewExecutionServer(ServerConfig{PublicKey: public, Issuer: "i", Audience: "a", AgentID: "g", Store: NewMemoryRunStore(), Capabilities: []string{"run", "resume", "cancel"}, Run: func(context.Context, ExecuteRequest, EventSink, <-chan struct{}) (map[string]any, error) {
		return nil, nil
	}}); err == nil {
		t.Fatal("run advertised without the events entry")
	}
	if _, err := NewExecutionServer(ServerConfig{PublicKey: public, Issuer: "i", Audience: "a", AgentID: "g", Store: NewMemoryRunStore(), Invoke: func(context.Context, ExecuteRequest) (map[string]any, error) { return nil, nil }}); err != nil {
		t.Fatalf("minimal invoke-only server rejected: %v", err)
	}
}

func TestServerRejectsSignedScopeForAnotherAgent(t *testing.T) {
	kit := newFixtureServer(t, []string{"invoke", "run", "resume", "cancel", "events"}, nil)
	defer kit.server.Close()
	for _, operation := range []string{"invoke", "run", "resume", "cancel", "events"} {
		t.Run(operation, func(t *testing.T) {
			request := kit.executeRequest(t, "foreign-agent-run", operation, "foreign-agent-command")
			request.Scope.AgentID = "another-agent"
			path := "/internal/agent-execution/v2/invoke"
			var payload any = request
			if operation == "run" {
				path = "/internal/agent-execution/v2/runs"
			} else if operation != "invoke" {
				path = "/internal/agent-execution/v2/runs/foreign-agent-run/" + operation
			}
			if operation == "events" {
				event := EventRequest{ProtocolVersion: ProtocolVersion, Scope: request.Scope, PolicySnapshotHash: "snapshot-hash"}
				event.ContextToken = signEvent(t, kit.private, "platform-runtime-gateway", "sdk-test-agent", event, kit.now)
				request.ContextToken = event.ContextToken
				payload = event
			} else {
				request.ContextToken = signExecute(t, kit.private, "platform-runtime-gateway", "sdk-test-agent", operation, request, kit.now)
				payload = request
			}
			body, _ := json.Marshal(payload)
			httpRequest, _ := http.NewRequest(http.MethodPost, kit.server.URL+path, bytes.NewReader(body))
			httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
			response, err := kit.server.Client().Do(httpRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("foreign signed Agent scope accepted: status %d", response.StatusCode)
			}
		})
	}
}
