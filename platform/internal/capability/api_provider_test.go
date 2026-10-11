package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func apiTestBinding(endpoint string) APIBinding {
	return APIBinding{ToolName: "api.read.inspect", Endpoint: endpoint + "/approved", TenantID: "tenant", ApplicationID: "app", AgentIDs: []string{"agent"}, ReadOnly: true, TimeoutSeconds: 1, MaxResponseBytes: 1024, QueryKeys: []string{"q"}, InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}},"additionalProperties":false}`)}
}
func apiTestCommand() ToolCommand {
	return ToolCommand{Name: "api.read.inspect", CallID: "call", Payload: map[string]any{"q": "hello & world"}, Scope: sharedkernel.Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", PrincipalID: "user", PrincipalType: "user", AgentID: "agent", AgentVersionID: "v1", AgentInstanceID: "instance", InstallationID: "install", RunID: "run", SessionID: "session", TraceID: "trace", AuthorizationEpoch: 1}}
}

func TestAPIToolFixedScopeQueryAndPrecision(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/approved" || r.URL.Query().Get("q") != "hello & world" {
			t.Errorf("unexpected request")
		}
		fmt.Fprint(w, `{"sequence":9007199254740993,"status":"ready"}`)
	}))
	defer server.Close()
	binding := apiTestBinding(server.URL)
	provider, err := NewAPIToolProvider([]APIBinding{binding}, nil, true, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	binding.AgentIDs[0] = "other" // Registration freezes caller-owned slices.
	result, err := provider.Invoke(context.Background(), apiTestCommand())
	if err != nil || result["sequence"] != json.Number("9007199254740993") {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if calls.Load() != 1 || provider.ExecutionType("api.read.inspect") != "api" {
		t.Fatal("API executor not selected")
	}
	for _, change := range []func(*ToolCommand){func(c *ToolCommand) { c.Scope.TenantID = "other" }, func(c *ToolCommand) { c.Scope.ApplicationID = "other" }, func(c *ToolCommand) { c.Scope.AgentID = "other" }, func(c *ToolCommand) { c.Scope.AuthorizationEpoch = 0 }, func(c *ToolCommand) { c.Payload = map[string]any{"endpoint": server.URL} }, func(c *ToolCommand) { c.Payload = map[string]any{"q": 123} }} {
		command := apiTestCommand()
		change(&command)
		if _, err := provider.Invoke(context.Background(), command); !errors.Is(err, ErrToolNotSubmitted) {
			t.Fatal("invalid command was not rejected")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("denied request reached upstream")
	}
}

func TestAPIToolRejectsUnsafeRegistration(t *testing.T) {
	for _, change := range []func(*APIBinding){func(b *APIBinding) { b.Endpoint = "http://169.254.169.254/latest/meta-data" }, func(b *APIBinding) { b.Endpoint = "https://example.com/api?token=secret" }, func(b *APIBinding) { b.Endpoint = "https://user:password@example.com/api" }, func(b *APIBinding) { b.ReadOnly = false }, func(b *APIBinding) { b.AgentIDs = nil }, func(b *APIBinding) { b.TimeoutSeconds = 6 }, func(b *APIBinding) { b.QueryKeys = []string{"secret_ref"} }, func(b *APIBinding) { b.SecretRef = "unresolved" }} {
		binding := apiTestBinding("https://example.com")
		change(&binding)
		if _, err := NewAPIToolProvider([]APIBinding{binding}, nil, false, modelgateway.NewGuardedEndpointClient); err == nil {
			t.Fatal("unsafe binding accepted")
		}
	}
}

func TestAPIToolResponseFailureNeverLeaksBodyOrRetries(t *testing.T) {
	for _, kind := range []string{"redirect", "error", "oversized", "invalid", "trailing", "timeout", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var calls, redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch kind {
				case "redirect":
					http.Redirect(w, r, target.URL, 302)
				case "error":
					w.WriteHeader(500)
					fmt.Fprint(w, "private upstream password")
				case "oversized":
					fmt.Fprint(w, strings.Repeat("x", 2048))
				case "invalid":
					fmt.Fprint(w, "private upstream password")
				case "trailing":
					fmt.Fprint(w, `{"ok":true}{"extra":true}`)
				default:
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			provider, err := NewAPIToolProvider([]APIBinding{apiTestBinding(server.URL)}, nil, true, modelgateway.NewGuardedEndpointClient)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			}
			started := time.Now()
			_, err = provider.Invoke(ctx, apiTestCommand())
			if err == nil || !errors.Is(err, ErrToolNotSubmitted) || strings.Contains(err.Error(), "password") || calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatalf("unsafe failure: %v calls=%d redirects=%d", err, calls.Load(), redirected.Load())
			}
			if (kind == "timeout" || kind == "cancelled") && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second) {
				t.Fatal("timeout not enforced")
			}
		})
	}
}

func TestAPIRegistrationPreservesBuiltinAndRejectsCollision(t *testing.T) {
	provider, err := NewAPIToolProvider([]APIBinding{apiTestBinding("https://example.com")}, nil, false, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	module := &Module{tools: builtinToolProvider{}}
	if module.SetAPIToolProvider(provider) != nil || !module.tools.Supports("clock.now") || !module.tools.Supports("api.read.inspect") {
		t.Fatal("registration lost builtin tool")
	}
	if module.SetAPIToolProvider(provider) == nil {
		t.Fatal("duplicate registration accepted")
	}
	if toolExecutionType(module.tools, "api.read.inspect") != "api" || toolExecutionType(module.tools, "clock.now") != "tool" {
		t.Fatal("incorrect execution type")
	}
}
