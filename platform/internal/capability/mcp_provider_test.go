package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPUncertainReceiptDoesNotRetryRemoteSideEffect(t *testing.T) {
	var effects atomic.Int32
	schema := json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
	server := mcp.NewServer(&mcp.Implementation{Name: "effect-test", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "apply", InputSchema: schema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		effects.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "applied"}}}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var request struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &request)
		if request.Method == "tools/call" {
			// The actual MCP server executes the tool, then its receipt is lost.
			captured := httptest.NewRecorder()
			handler.ServeHTTP(captured, r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("broken receipt"))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer endpoint.Close()
	provider, err := NewMCPToolProvider([]MCPBinding{{ToolName: "mcp.test.apply", RemoteName: "apply", Endpoint: endpoint.URL, InputSchema: schema}}, nil, true, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Invoke(context.Background(), ToolCommand{Scope: mcpTestScope(), Name: "mcp.test.apply", CallID: "one-effect", Payload: map[string]any{}})
	if err == nil || errors.Is(err, ErrToolNotSubmitted) || effects.Load() != 1 {
		t.Fatalf("uncertain side effect was retried or classified as unsent: error=%v effects=%d", err, effects.Load())
	}
}

func mcpTestScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", PrincipalID: "user", PrincipalType: "user", AgentID: "agent", AgentInstanceID: "instance", AgentVersionID: "v1", InstallationID: "install", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
}

func TestMCPActualHTTPDiscoverySchemaPinAndInvocation(t *testing.T) {
	var count atomic.Int32
	schema := json.RawMessage(`{"type":"object","properties":{"question":{"type":"string"}},"required":["question"],"additionalProperties":false}`)
	server := mcp.NewServer(&mcp.Implementation{Name: "test-knowledge", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "search", InputSchema: schema}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		count.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "verified teaching result"}}}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	endpoint := httptest.NewServer(handler)
	defer endpoint.Close()
	binding := MCPBinding{ToolName: "mcp.docs.search", RemoteName: "search", Endpoint: endpoint.URL, InputSchema: schema}
	provider, err := NewMCPToolProvider([]MCPBinding{binding}, nil, true, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	command := ToolCommand{Scope: mcpTestScope(), Name: binding.ToolName, CallID: "call-1", Payload: map[string]any{"question": "How do leases work?"}}
	result, err := provider.Invoke(context.Background(), command)
	if err != nil || result["protocol"] != "mcp" || count.Load() != 1 {
		t.Fatalf("MCP round trip failed: %+v %v count=%d", result, err, count.Load())
	}
	command.Payload = map[string]any{"question": 42}
	if _, err = provider.Invoke(context.Background(), command); !errors.Is(err, ErrToolNotSubmitted) || count.Load() != 1 {
		t.Fatal("invalid schema reached tool")
	}
	command.Payload = map[string]any{"question": "another question"}
	binding.InputSchema = json.RawMessage(`{"type":"object","properties":{"question":{"type":"string"}},"required":["question"]}`)
	provider, err = NewMCPToolProvider([]MCPBinding{binding}, nil, true, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Invoke(context.Background(), command); !errors.Is(err, ErrToolNotSubmitted) || count.Load() != 1 {
		t.Fatal("schema drift invoked remote tool")
	}
}

func TestMCPBindingsRejectUnownedAndUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://192.168.1.2/mcp", "https://user:password@example.com/mcp", "https://example.com/mcp?key=value", "file:///tmp/server", "https://example.com:9999/mcp"} {
		_, err := NewMCPToolProvider([]MCPBinding{{ToolName: "mcp.docs.search", RemoteName: "search", Endpoint: endpoint, InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil, false, modelgateway.NewGuardedEndpointClient)
		if err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	_, err := NewMCPToolProvider([]MCPBinding{{ToolName: "runtime.inspect", RemoteName: "inspect", Endpoint: "https://example.com/mcp", InputSchema: json.RawMessage(`{"type":"object"}`)}}, nil, false, modelgateway.NewGuardedEndpointClient)
	if err == nil {
		t.Fatal("built-in tool shadowing accepted")
	}
}
