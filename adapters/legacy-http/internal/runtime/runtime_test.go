package runtime

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/legacy-http-adapter/internal/planloader"
)

const (
	testIssuer   = "lexagent-adapter-test"
	testPlanHash = "h1"
	planDocument = `{"mapping_id":"legacy-ask","version":"1.0.0","kind":"legacy-http","revision":2,"hash":"h1","request":{"question":{"source":"input.question"}},"response":{"answer":{"source":"body.answer"}}}`
)

type issuer struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newIssuer(t *testing.T) issuer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issuer{public: public, private: private}
}

func (i issuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA"})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(i.private, []byte(h+"."+p)))
}

// request builds a body that satisfies the platform PEP, including the body hash
// binding, so the adapter's own verification is genuinely exercised.
// request 构造一个满足平台 PEP（含请求体哈希绑定）的请求体，从而真正演练 Adapter
// 自身的校验逻辑。
func (i issuer) request(t *testing.T, input map[string]any) ([]byte, string) {
	t.Helper()
	payload := map[string]any{"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"}}
	for key, value := range input {
		payload[key] = value
	}
	req := agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		Operation:       "invoke",
		IdempotencyKey:  "idem-1",
		InputSchema:     "schema://legacy/input/v1",
		Input:           payload,
		Scope: agentplatform.ScopeKey{
			TenantID: "tenant-a", ApplicationID: "app-a", AgentInstanceID: "instance-1", InstallationID: "installation-1",
			PrincipalType: "user", PrincipalID: "user-1", RunID: "run-1",
			AuthorizationEpoch: 1, TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
	}
	hash, err := agentplatform.CanonicalBodyHash(req)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	req.ContextToken = i.sign(t, map[string]any{
		"iss": testIssuer, "aud": "agent-runtime", "subject_type": "user", "sub": "user-1",
		"tenant_id": "tenant-a", "application_id": "app-a", "agent_instance_id": "instance-1", "installation_id": "installation-1",
		"authorization_epoch": 1, "actions": []string{"invoke"},
		"policy_snapshot_hash": "snapshot-hash", "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw, req.ContextToken
}

// lkgLoader returns a loader already holding a verified last-known-good plan.
// lkgLoader 返回一个已持有校验通过的 LKG 计划的加载器。
func lkgLoader(t *testing.T) *planloader.Loader {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(planDocument)
	envelope := []byte(`{"signature":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(private, body)) + `","plan":` + string(body) + `}`)
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	loader := &planloader.Loader{Path: path, PublicKey: public, ExpectedHash: testPlanHash, MinRevision: 1}
	if _, err := loader.Refresh(); err != nil {
		t.Fatal(err)
	}
	return loader
}

func config(t *testing.T, upstream *url.URL, plans *planloader.Loader) Config {
	t.Helper()
	return Config{
		Development:      true,
		Upstream:         upstream,
		Path:             "/invoke",
		ExpectedHash:     testPlanHash,
		MappingRequired:  true,
		Plans:            plans,
		ContextPublicKey: nil,
		ContextIssuer:    testIssuer,
		AgentID:          "legacy-agent",
	}
}

func invoke(t *testing.T, handler http.Handler, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/invoke", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestInvokeCompletesL1WithRegisteredPlanOnly is the PF-11 acceptance case: a
// legacy agent is onboarded with a mapping document and no code, and the adapter
// completes an L1 invoke without the caller supplying any plan.
// TestInvokeCompletesL1WithRegisteredPlanOnly 是 PF-11 验收场景：存量 Agent 仅凭一份
// 映射文档、无需改代码，且调用方不提供任何计划，Adapter 也能完成 L1 invoke。
func TestInvokeCompletesL1WithRegisteredPlanOnly(t *testing.T) {
	identity := newIssuer(t)
	var received map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &received)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("credential header reached the legacy upstream: %v", r.Header)
		}
		if r.Header.Get("Idempotency-Key") != "idem-1" {
			t.Errorf("idempotency key was not propagated: %v", r.Header)
		}
		if !strings.HasPrefix(r.Header.Get("Traceparent"), "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
			t.Errorf("trace context was not propagated: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"4"}`))
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, lkgLoader(t))
	cfg.ContextPublicKey = identity.public
	handler := NewHandler(cfg)

	body, token := identity.request(t, map[string]any{"question": "what is 2+2?"})
	recorder := invoke(t, handler, body, token)
	if recorder.Code != http.StatusOK {
		t.Fatalf("invoke failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if received["question"] != "what is 2+2?" || received["mapping_plan"] != nil {
		t.Fatalf("mapping was not applied before reaching the upstream: %v", received)
	}
	var response struct {
		Status string         `json:"status"`
		Output map[string]any `json:"output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "succeeded" || response.Output["answer"] != "4" {
		t.Fatalf("response mapping was not applied: %+v", response)
	}
}

func TestInvokeRefusesCallerSuppliedPlanWhenNothingIsPinned(t *testing.T) {
	identity := newIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"4"}`))
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, nil)
	cfg.ContextPublicKey = identity.public
	cfg.ExpectedHash = ""
	cfg.MappingRequired = false

	body, token := identity.request(t, map[string]any{
		"mapping_plan": json.RawMessage(planDocument),
	})
	recorder := invoke(t, NewHandler(cfg), body, token)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unpinnable caller plan was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

// TestInvokeDoesNotFollowUpstreamRedirect keeps a compromised legacy endpoint
// from moving the platform's verified egress to a host that never passed the
// descriptor's address policy.
// TestInvokeDoesNotFollowUpstreamRedirect 阻止被攻陷的存量端点把平台已校验的出站
// 流量引到一个从未通过 Descriptor 地址策略的主机。
func TestInvokeDoesNotFollowUpstreamRedirect(t *testing.T) {
	identity := newIssuer(t)
	redirected := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"stolen"}`))
	}))
	defer elsewhere.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, lkgLoader(t))
	cfg.ContextPublicKey = identity.public

	body, token := identity.request(t, map[string]any{"question": "q"})
	recorder := invoke(t, NewHandler(cfg), body, token)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("a redirect was not rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	if redirected != 0 {
		t.Fatalf("the adapter followed the upstream redirect %d time(s)", redirected)
	}
}

// TestInvokeDoesNotLeakUpstreamErrorDetail keeps a legacy Agent's diagnostics
// (internal hostnames, credentials, stack traces) out of the platform response.
// TestInvokeDoesNotLeakUpstreamErrorDetail 阻止存量 Agent 的诊断信息（内部主机名、
// 凭据、栈回溯）出现在平台响应里。
func TestInvokeDoesNotLeakUpstreamErrorDetail(t *testing.T) {
	identity := newIssuer(t)
	const secret = "internal-db.prod.local password=hunter2"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"` + secret + `"}`))
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, lkgLoader(t))
	cfg.ContextPublicKey = identity.public

	body, token := identity.request(t, map[string]any{"question": "q"})
	recorder := invoke(t, NewHandler(cfg), body, token)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "internal-db.prod.local") || strings.Contains(recorder.Body.String(), "hunter2") {
		t.Fatalf("upstream error detail leaked to the caller: %q", recorder.Body.String())
	}
}

func TestInvokeRejectsUnverifiableCapability(t *testing.T) {
	identity := newIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"4"}`))
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, lkgLoader(t))
	cfg.ContextPublicKey = identity.public

	body, _ := identity.request(t, map[string]any{"question": "q"})
	if recorder := invoke(t, NewHandler(cfg), body, "not-a-capability"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unverifiable capability was accepted: %d", recorder.Code)
	}
}

// eventRequest builds an execution-event subscription that satisfies the
// platform PEP for the "events" action.
// eventRequest 构造一个满足平台 PEP（events 动作）的执行事件订阅请求。
func (i issuer) eventRequest(t *testing.T, runID string, afterSeq uint64) ([]byte, string) {
	t.Helper()
	req := agentplatform.EventRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		Scope: agentplatform.ScopeKey{
			TenantID: "tenant-a", ApplicationID: "app-a", AgentInstanceID: "instance-1", InstallationID: "installation-1",
			PrincipalType: "user", PrincipalID: "user-1", RunID: runID,
			AuthorizationEpoch: 1, TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		AfterSeq:           afterSeq,
		PolicySnapshotHash: "snapshot-hash",
	}
	hash, err := agentplatform.CanonicalEventHash(req)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	req.ContextToken = i.sign(t, map[string]any{
		"iss": testIssuer, "aud": "agent-runtime", "subject_type": "user", "sub": "user-1",
		"tenant_id": "tenant-a", "application_id": "app-a", "agent_instance_id": "instance-1", "installation_id": "installation-1",
		"authorization_epoch": 1, "actions": []string{"events"},
		"policy_snapshot_hash": "snapshot-hash", "body_hash": hash,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(),
	})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw, req.ContextToken
}

const testEventsPath = "/events"

func eventsConfig(t *testing.T, upstream *url.URL, eventsPath string) Config {
	t.Helper()
	cfg := config(t, upstream, lkgLoader(t))
	cfg.EventsPath = eventsPath
	return cfg
}

// adapterServer exposes the handler over a real socket so streaming behaviour
// (incremental delivery) can be observed; a ResponseRecorder would buffer it.
// adapterServer 通过真实 socket 暴露处理器，以便观测流式行为（增量投递）；
// ResponseRecorder 会把内容缓冲起来。
func adapterServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func writeEventFrame(w io.Writer, seq uint64, runID, eventType string) {
	event := agentplatform.ExecutionEvent{RunID: runID, Seq: seq, EventType: eventType, OccurredAt: time.Now().UTC(), Payload: map[string]any{"n": seq}}
	raw, _ := json.Marshal(event)
	_, _ = w.Write([]byte("id: " + strconv.FormatUint(seq, 10) + "\nevent: " + eventType + "\ndata: " + string(raw) + "\n\n"))
}

// readEventFrame reads one SSE frame, mirroring the platform's framing contract.
// readEventFrame 读取一个 SSE 帧，与平台的帧格式契约一致。
func readEventFrame(t *testing.T, reader *bufio.Reader) (id, eventType, data string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before a complete frame: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if id != "" || eventType != "" || data != "" {
				return id, eventType, data
			}
		case strings.HasPrefix(line, "id: "):
			id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

// TestEventsRelaysUpstreamStreamToCaller is the PF-11 SSE acceptance case: the
// adapter exposes the platform event path, verifies the event capability, and
// relays well-formed frames from the legacy upstream.
// TestEventsRelaysUpstreamStreamToCaller 是 PF-11 的 SSE 验收场景：Adapter 暴露
// 平台事件路径、校验事件能力，并把存量上游的合规帧转发给调用方。
func TestEventsRelaysUpstreamStreamToCaller(t *testing.T) {
	identity := newIssuer(t)
	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != testEventsPath {
			t.Errorf("adapter dialed an unexpected upstream path: %s", r.URL.Path)
		}
		upstreamHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		writeEventFrame(w, 1, "run-1", "started")
		writeEventFrame(w, 2, "run-1", "completed")
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventsConfig(t, target, testEventsPath)
	cfg.ContextPublicKey = identity.public
	adapter := adapterServer(t, NewHandler(cfg))

	body, token := identity.eventRequest(t, "run-1", 7)
	request, err := http.NewRequest(http.MethodPost, adapter.URL+"/internal/agent-execution/v2/runs/run-1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Cookie", "session=caller-session")
	response, err := adapter.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("events endpoint did not stream: %d %s", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	id, eventType, data := readEventFrame(t, reader)
	if id != "1" || eventType != "started" || !strings.Contains(data, `"run_id":"run-1"`) {
		t.Fatalf("first frame was not relayed faithfully: id=%q event=%q data=%q", id, eventType, data)
	}
	if id, eventType, _ = readEventFrame(t, reader); id != "2" || eventType != "completed" {
		t.Fatalf("second frame was not relayed faithfully: id=%q event=%q", id, eventType)
	}
	if upstreamHeaders.Get("Authorization") != "" || upstreamHeaders.Get("Cookie") != "" {
		t.Fatalf("credential header reached the legacy upstream: %v", upstreamHeaders)
	}
	if !strings.HasPrefix(upstreamHeaders.Get("Traceparent"), "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Fatalf("trace context was not propagated to the event stream: %v", upstreamHeaders)
	}
	if upstreamHeaders.Get("Last-Event-ID") != "7" {
		t.Fatalf("SSE resume position was not propagated: %q", upstreamHeaders.Get("Last-Event-ID"))
	}
	if upstreamHeaders.Get("Idempotency-Key") != "" {
		t.Fatalf("an event subscription must not carry an idempotency key: %q", upstreamHeaders.Get("Idempotency-Key"))
	}
}

// TestEventsStreamsIncrementally proves frames are relayed as they arrive; a
// buffering implementation would hold the first frame until the upstream closed.
// TestEventsStreamsIncrementally 证明帧是随到随转发；缓冲实现会把第一帧扣到上游
// 关闭之后才发出。
func TestEventsStreamsIncrementally(t *testing.T) {
	identity := newIssuer(t)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		writeEventFrame(w, 1, "run-1", "started")
		http.NewResponseController(w).Flush()
		<-release
		writeEventFrame(w, 2, "run-1", "completed")
		http.NewResponseController(w).Flush()
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventsConfig(t, target, testEventsPath)
	cfg.ContextPublicKey = identity.public
	adapter := adapterServer(t, NewHandler(cfg))

	body, token := identity.eventRequest(t, "run-1", 0)
	request, err := http.NewRequest(http.MethodPost, adapter.URL+"/internal/agent-execution/v2/runs/run-1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := adapter.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if id, eventType, _ := readEventFrame(t, reader); id != "1" || eventType != "started" {
		t.Fatalf("the first frame was withheld until the upstream finished: id=%q event=%q", id, eventType)
	}
	close(release)
	if id, eventType, _ := readEventFrame(t, reader); id != "2" || eventType != "completed" {
		t.Fatalf("the resumed frame was not relayed: id=%q event=%q", id, eventType)
	}
}

func TestEventsReportUnsupportedCapabilityWhenNotDeclared(t *testing.T) {
	identity := newIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventsConfig(t, target, "") // no events path declared
	cfg.ContextPublicKey = identity.public
	handler := NewHandler(cfg)

	body, token := identity.eventRequest(t, "run-1", 0)
	request := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/runs/run-1/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotImplemented || !strings.Contains(recorder.Body.String(), EventsUnsupportedCode) {
		t.Fatalf("undeclared events capability was not reported explicitly: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestEventsRejectUnverifiableCapabilityAndForeignPaths(t *testing.T) {
	identity := newIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := eventsConfig(t, target, testEventsPath)
	cfg.ContextPublicKey = identity.public
	handler := NewHandler(cfg)

	body, _ := identity.eventRequest(t, "run-1", 0)
	request := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/runs/run-1/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer forged")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unverifiable event capability was accepted: %d", recorder.Code)
	}

	// A run id that does not match the subscription scope is refused.
	body, token := identity.eventRequest(t, "run-1", 0)
	request = httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/runs/run-2/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a mismatched run id was accepted: %d", recorder.Code)
	}

	// A checkpoint path is not an event stream.
	request = httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/runs/run-1/checkpoint", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("a non-events path was served by the events handler: %d", recorder.Code)
	}
}

func TestManifestAdvertisesEventsOnlyWhenConfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	readCapabilities := func(cfg Config) []any {
		recorder := httptest.NewRecorder()
		NewHandler(cfg).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/agent-manifest.json", nil))
		var manifest map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &manifest); err != nil {
			t.Fatal(err)
		}
		capabilities, _ := manifest["capabilities"].([]any)
		return capabilities
	}
	withoutEvents := eventsConfig(t, target, "")
	if capabilities := readCapabilities(withoutEvents); len(capabilities) != 1 || capabilities[0] != "invoke" {
		t.Fatalf("manifest advertised events without an events path: %v", capabilities)
	}
	withEvents := eventsConfig(t, target, testEventsPath)
	capabilities := readCapabilities(withEvents)
	found := false
	for _, capability := range capabilities {
		if capability == "events" {
			found = true
		}
	}
	if !found {
		t.Fatalf("manifest did not advertise the declared events capability: %v", capabilities)
	}
}

func TestHealthReportsPlanRevisionAndDegrade(t *testing.T) {
	loader := lkgLoader(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, target, loader)
	handler := NewHandler(cfg)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	var status map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["plan_revision"] != float64(2) || status["plan_degraded"] != false || status["plan_digest"] == nil {
		t.Fatalf("health did not expose the plan state: %v", status)
	}
}
