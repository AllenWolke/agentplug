package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func TestRejectsUnregisteredUpstreamWithoutContactingIt(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer upstream.Close()

	_, err := (Proxy{BaseURL: upstream.URL}).Invoke(context.Background(), validRequest())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("unregistered upstream was contacted %d time(s)", got)
	}
}

func TestForwardsOnlySignedCapabilityToRegisteredUpstream(t *testing.T) {
	var authorization atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol_version":"agent-execution/v2","run_id":"run-1","status":"succeeded"}`))
	}))
	defer upstream.Close()

	request := validRequest()
	request.ContextToken = "signed-capability"
	output, err := (Proxy{BaseURL: upstream.URL, Client: upstream.Client()}).Invoke(context.Background(), request)
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if output.RunID != request.Scope.RunID || output.Status != "succeeded" {
		t.Fatalf("unexpected response: %+v", output)
	}
	if got := authorization.Load(); got != "Bearer signed-capability" {
		t.Fatalf("authorization header = %q, want only signed capability", got)
	}
}

func validRequest() agentplatform.ExecuteRequest {
	return agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		ContextToken:    "",
		Operation:       "invoke",
		InputSchema:     "schema://sidecar/test-input",
		IdempotencyKey:  "sidecar-test-idem",
		Input:           map[string]any{"message": "test"},
		Scope:           agentplatform.ScopeKey{RunID: "run-1"},
	}
}

// TestStreamEventsRelaysRegisteredUpstreamStream drives a real two-server SSE
// round trip: frames arrive at the caller and the resume handshake is forwarded.
// TestStreamEventsRelaysRegisteredUpstreamStream 通过真实的两段式 SSE 往返验证：
// 帧到达调用方，且恢复握手被转发到上游。
func TestStreamEventsRelaysRegisteredUpstreamStream(t *testing.T) {
	var lastEventID atomic.Value
	var authorization atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastEventID.Store(r.Header.Get("Last-Event-ID"))
		authorization.Store(r.Header.Get("Authorization"))
		if want := "text/event-stream"; r.Header.Get("Accept") != want {
			t.Errorf("accept header = %q, want %q", r.Header.Get("Accept"), want)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("id: 1\nevent: step\ndata: {\"a\":1}\n\n"))
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	service := Proxy{BaseURL: upstream.URL, Client: upstream.Client()}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := service.StreamEvents(r.Context(), agentplatform.EventRequest{
			ProtocolVersion: agentplatform.ProtocolVersion,
			ContextToken:    "signed-events-capability",
			AfterSeq:        3,
			Scope:           agentplatform.ScopeKey{RunID: "run-1"},
		}, "/events", w, 1<<20)
		if err != nil {
			t.Errorf("StreamEvents() error = %v", err)
		}
	}))
	defer front.Close()

	response, err := http.Get(front.URL)
	if err != nil {
		t.Fatalf("read relayed stream: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "id: 1") || !strings.Contains(string(body), "event: step") {
		t.Fatalf("relayed stream lost frames: %q", body)
	}
	if got := lastEventID.Load(); got != "3" {
		t.Fatalf("Last-Event-ID = %v, want 3", got)
	}
	if got := authorization.Load(); got != "Bearer signed-events-capability" {
		t.Fatalf("authorization header = %v, want only the signed capability", got)
	}
}

// TestStreamEventsRefusesUnregisteredPathWithoutContactingUpstream proves the
// events relay cannot be pointed at an arbitrary upstream path.
// TestStreamEventsRefusesUnregisteredPathWithoutContactingUpstream 证明事件转发
// 无法被指向任意上游路径。
func TestStreamEventsRefusesUnregisteredPathWithoutContactingUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	service := Proxy{BaseURL: upstream.URL, Client: upstream.Client()}
	if err := service.StreamEvents(context.Background(), agentplatform.EventRequest{}, "", httptest.NewRecorder(), 1<<20); !errors.Is(err, ErrEventStream) {
		t.Fatalf("empty events path was accepted: %v", err)
	}
	if err := service.StreamEvents(context.Background(), agentplatform.EventRequest{}, "../secrets", httptest.NewRecorder(), 1<<20); !errors.Is(err, ErrEventStream) {
		t.Fatalf("traversing events path was accepted: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream was contacted for a refused events request %d time(s)", got)
	}
}
