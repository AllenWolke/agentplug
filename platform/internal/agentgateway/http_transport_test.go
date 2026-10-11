package agentgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
)

func TestHTTPTransportPreservesDomainPolicyAndUpstreamClassification(t *testing.T) {
	for _, tc := range []struct {
		code      string
		status    int
		retryable bool
	}{
		{"RULE_BUNDLE_INVALID", 422, false}, {"POLICY_DENIED", 403, false},
		{"UNSUPPORTED_REPORT_TYPE", 422, false}, {"CAPABILITY_UNAVAILABLE", 503, true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if err := json.NewEncoder(w).Encode(contract.AppError{Code: tc.code, Message: "fixed safe failure", Retryable: tc.retryable}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			response, err := NewHTTPTransport(server.Client()).Invoke(context.Background(), httpTarget(server.URL), testRequest("invoke"))
			var typed contract.AppError
			if !errors.As(err, &typed) || typed.Code != tc.code || typed.Retryable != tc.retryable || response.Status != "" {
				t.Fatalf("HTTP classification lost: response=%+v err=%v", response, err)
			}
			var completed CompletedExecutionFailure
			if errors.As(err, &completed) {
				t.Fatalf("bare HTTP AppError acquired a terminal-envelope proof: %+v", completed.Response)
			}
		})
	}
}

func httpTarget(serverURL string) Target {
	return Target{InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", Endpoint: serverURL, Transport: "http", Revision: 1, ManifestHash: "manifest"}
}

func TestHTTPTransportBindsSDKTerminalFailureToExactRun(t *testing.T) {
	for _, tc := range []struct {
		name, version, run, status string
		known                      bool
		message                    string
		includeError               bool
		handoff                    bool
	}{
		{"completed-sdk-failure", contract.ProtocolVersion, "run", "failed", true, "known billable output was truncated", true, false},
		{"foreign-run", contract.ProtocolVersion, "foreign", "failed", false, "known billable output was truncated", true, false},
		{"missing-terminal-state", contract.ProtocolVersion, "run", "", false, "known billable output was truncated", true, false},
		{"wrong-protocol", "agent-execution/v1", "run", "failed", false, "known billable output was truncated", true, false},
		{"nonterminal-with-error", contract.ProtocolVersion, "run", "succeeded", false, "known billable output was truncated", true, false},
		{"missing-error", contract.ProtocolVersion, "run", "failed", false, "", false, false},
		{"missing-error-message", contract.ProtocolVersion, "run", "failed", false, "", true, false},
		{"handoff-on-failure", contract.ProtocolVersion, "run", "failed", false, "known billable output was truncated", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				response := contract.ExecuteResponse{ProtocolVersion: tc.version, RunID: tc.run, Status: tc.status}
				if tc.includeError {
					response.Error = &contract.AppError{Code: "MODEL_OUTPUT_INCOMPLETE", Message: tc.message, Retryable: false}
				}
				if tc.handoff {
					response.Handoff = &contract.HandlerHandoff{}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			_, err := NewHTTPTransport(server.Client()).Invoke(context.Background(), httpTarget(server.URL), testRequest("invoke"))
			var failure contract.AppError
			var completed CompletedExecutionFailure
			if tc.known {
				if !errors.As(err, &failure) || failure.Code != "MODEL_OUTPUT_INCOMPLETE" || failure.Retryable ||
					!errors.As(err, &completed) || completed.Response.ProtocolVersion != contract.ProtocolVersion ||
					completed.Response.RunID != "run" || completed.Response.Status != "failed" || completed.Response.Error == nil {
					t.Fatal("completed SDK failure lost its classification", err)
				}
			} else if !errors.Is(err, ErrHTTPInvalidResponse) || errors.As(err, &failure) || errors.As(err, &completed) {
				t.Fatal("unbound failure incorrectly treated as a completed command", err)
			}
		})
	}
}

func TestHTTPTransportExecutesV2AndPropagatesAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/agent-execution/v2/invoke" || r.Header.Get("Authorization") != "Bearer "+testRequest("invoke").ContextToken {
			t.Fatalf("unexpected request path/auth: %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol_version":"agent-execution/v2","run_id":"run","status":"succeeded"}`))
	}))
	defer server.Close()

	response, err := NewHTTPTransport(server.Client()).Invoke(context.Background(), httpTarget(server.URL), testRequest("invoke"))
	if err != nil || response.Status != "succeeded" || response.RunID != "run" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}

func TestHTTPTransportRejectsInvalidResponseAndAppError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/agent-execution/v2/invoke" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"succeeded"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"PERMISSION_DENIED","message":"denied","retryable":false}`))
	}))
	defer server.Close()
	transport := NewHTTPTransport(server.Client())
	if _, err := transport.Invoke(context.Background(), httpTarget(server.URL), testRequest("invoke")); !errors.Is(err, ErrHTTPInvalidResponse) {
		t.Fatalf("expected invalid response, got %v", err)
	}
	request := testRequest("run")
	if _, err := transport.Run(context.Background(), httpTarget(server.URL), request); err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("expected stable app error, got %v", err)
	}
}

func TestHTTPTransportEventsValidatesSSEAndPropagatesProtocolError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: 1\nevent: status\ndata: {\"run_id\":\"run\",\"seq\":1,\"event_type\":\"status\",\"payload\":{}}\n\n"))
	}))
	defer server.Close()
	request := contract.EventRequest{ProtocolVersion: contract.ProtocolVersion, ContextToken: testRequest("events").ContextToken, Scope: testScope(), PolicySnapshotHash: strings.Repeat("a", 64)}
	stream, err := NewHTTPTransport(server.Client()).Events(context.Background(), httpTarget(server.URL), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-stream.Events:
		if event.Seq != 1 || event.EventType != "status" {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE event")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: invalid\nevent: status\ndata: {}\n\n"))
	}))
	defer malformed.Close()
	badStream, err := NewHTTPTransport(malformed.Client()).Events(context.Background(), httpTarget(malformed.URL), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case streamErr := <-badStream.Errors:
		if !errors.Is(streamErr, ErrHTTPEventProtocol) {
			t.Fatalf("expected event protocol error, got %v", streamErr)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE protocol error")
	}
}
