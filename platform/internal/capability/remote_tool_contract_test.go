package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolOperationIdentitySeparatesIntentAttemptAndArguments(t *testing.T) {
	fingerprint, err := ToolCommandFingerprint("mcp.apply", map[string]any{"a": "x", "n": json.Number("9007199254740993")})
	if err != nil {
		t.Fatal(err)
	}
	q := ToolReceiptQuery{Scope: mcpTestScope(), Name: "mcp.apply", CallID: "stable-step", Fingerprint: fingerprint}
	first, err := NewToolOperationIdentity(q)
	if err != nil {
		t.Fatal(err)
	}
	q.Scope.TraceID = "next-trace"
	q.Scope.AuthorizationEpoch++ // Current authority is checked independently.
	second, err := NewToolOperationIdentity(q)
	if err != nil || first != second {
		t.Fatal("observational/authorization renewal changed the business intent", err)
	}
	q.Fingerprint = strings.Repeat("e", 64)
	changed, err := NewToolOperationIdentity(q)
	if err != nil || changed.OperationID != first.OperationID || changed.RequestSHA256 == first.RequestSHA256 {
		t.Fatal("argument changes were hidden in a new operation identity")
	}
	q.Scope.RunID = "new-run"
	rerun, _ := NewToolOperationIdentity(q)
	if rerun.OperationID == first.OperationID {
		t.Fatal("rerun reused original external identity")
	}
	for _, mutate := range []func(*ToolReceiptQuery){
		func(q *ToolReceiptQuery) { q.Scope.RunID = "" },
		func(q *ToolReceiptQuery) { q.CallID = "unsafe\r\nheader" },
		func(q *ToolReceiptQuery) { q.Fingerprint = "not-a-digest" },
	} {
		bad := q
		mutate(&bad)
		if _, err := NewToolOperationIdentity(bad); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestRemoteToolContractRejectsUnprovenGuarantees(t *testing.T) {
	valid := conservativeRemoteContract()
	if valid.Validate() != nil {
		t.Fatal("conservative contract rejected")
	}
	for _, mutate := range []func(*RemoteToolContract){
		func(c *RemoteToolContract) { c.Version = "unknown" },
		func(c *RemoteToolContract) { c.Idempotency = "exactly_once" },
		func(c *RemoteToolContract) { c.Idempotency = "durable_key" },
		func(c *RemoteToolContract) { c.RetentionSeconds = 60 },
		func(c *RemoteToolContract) { c.ConflictRule = "overwrite" },
		func(c *RemoteToolContract) { c.ReceiptTool = "lookup" },
	} {
		bad := valid
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unproven guarantee accepted", bad)
		}
	}
}

// This fixture runs real MCP HTTP discovery, a real effect handler and a
// separately schema-pinned receipt handler. It corrupts only the effect reply.
func remoteEffectFixture(t *testing.T, mode string) (*MCPToolProvider, ToolCommand, RemoteToolContract, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var effects, lookups atomic.Int32
	applySchema := json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}`)
	lookupSchema := json.RawMessage(remoteReceiptInputSchema)
	lookupHash, _ := canonicalSchemaHash(lookupSchema)
	contract := RemoteToolContract{Version: "remote-tool-effects/v1", Idempotency: "durable_key", RetentionSeconds: 86400, ConflictRule: "reject_mismatch", ReceiptTool: "lookup", ReceiptSchema: lookupHash, ReceiptReadOnly: true}
	command := ToolCommand{Scope: mcpTestScope(), Name: "mcp.remote.apply", CallID: "one-intent", Payload: map[string]any{"value": "kept"}}
	fp, _ := ToolCommandFingerprint(command.Name, command.Payload)
	expected, _ := NewToolOperationIdentity(ToolReceiptQuery{Scope: command.Scope, Name: command.Name, CallID: command.CallID, Fingerprint: fp})
	original := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "applied once"}}, StructuredContent: map[string]any{"sequence": json.Number("9007199254740993")}}
	originalJSON, _ := json.Marshal(original)
	server := mcp.NewServer(&mcp.Implementation{Name: "isolated-effect-fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "apply", InputSchema: applySchema}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var actual ToolOperationIdentity
		meta, _ := json.Marshal(r.Params.Meta["agentplug.dev/operation"])
		if json.Unmarshal(meta, &actual) != nil || actual != expected {
			t.Error("stable identity did not reach actual effect handler")
		}
		effects.Add(1)
		return original, nil
	})
	if mode == "schema-drift" {
		lookupSchema = json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
	}
	server.AddTool(&mcp.Tool{Name: "lookup", InputSchema: lookupSchema}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		lookups.Add(1)
		var queried ToolOperationIdentity
		if json.Unmarshal(r.Params.Arguments, &queried) != nil || queried != expected {
			t.Error("lookup changed intent or replayed payload")
		}
		receipt := remoteToolReceipt{Version: "remote-tool-receipt/v1", Identity: expected, Status: "succeeded", ReceiptJSON: string(originalJSON)}
		switch mode {
		case "wrong-run":
			receipt.Identity.RunID = "other-run"
		case "wrong-digest":
			receipt.Identity.RequestSHA256 = strings.Repeat("a", 64)
		case "not-found":
			receipt.Status, receipt.ReceiptJSON = "not_found", ""
		case "unknown":
			receipt.Status, receipt.ReceiptJSON = "unknown", ""
		case "failed-final":
			receipt.Status, receipt.ReceiptJSON = "failed_final", ""
		}
		return &mcp.CallToolResult{StructuredContent: receipt}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AgentPlug-Operation-ID") != expected.OperationID || r.Header.Get("X-AgentPlug-Request-Digest") != expected.RequestSHA256 {
			t.Error("remote HTTP lost operation identity")
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var message struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &message)
		if message.Method == "tools/call" && message.Params.Name == "apply" {
			captured := httptest.NewRecorder()
			handler.ServeHTTP(captured, r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("lost response"))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(endpoint.Close)
	provider, err := NewMCPToolProvider([]MCPBinding{{ToolName: command.Name, RemoteName: "apply", Endpoint: endpoint.URL, InputSchema: applySchema, Effects: contract}}, nil, true, modelgateway.NewGuardedEndpointClient)
	if err != nil {
		t.Fatal(err)
	}
	contract, _ = provider.DescribeRemoteTool(command.Name)
	return provider, command, contract, &effects, &lookups
}

func TestRemoteToolLostResponseReconcilesOriginalWithoutReplay(t *testing.T) {
	for _, mode := range []string{"success", "wrong-run", "wrong-digest", "not-found", "unknown", "failed-final", "schema-drift", "contract-drift"} {
		t.Run(mode, func(t *testing.T) {
			provider, command, contract, effects, lookups := remoteEffectFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			fp, _ := ToolCommandFingerprint(command.Name, command.Payload)
			q := ToolReceiptQuery{Scope: command.Scope, Name: command.Name, CallID: command.CallID, Fingerprint: fp, RemoteContract: &contract}
			store := newMemoryToolInvocationStore()
			leaseCtx := context.WithValue(ctx, toolReceiptContextKey{}, q)
			record, _, err := store.AcquireTool(leaseCtx, ToolReceiptScopeHash(q.Scope), q.CallID, fp, "worker-a", time.Minute)
			if err != nil || store.BeginTool(ctx, record.Lease) != nil {
				t.Fatal("cannot admit effect", err)
			}
			if _, err := provider.Invoke(ctx, command); err == nil || errors.Is(err, ErrToolNotSubmitted) || effects.Load() != 1 {
				t.Fatal("lost reply misclassified or effect not executed exactly once", err)
			}
			if err := store.UnknownTool(ctx, record.Lease); err != nil {
				t.Fatal(err)
			}
			if mode == "contract-drift" {
				b := provider.tools[command.Name]
				b.binding.Effects.RetentionSeconds++
				provider.tools[command.Name] = b
			}
			dispatcher, err := NewExecutionDispatcher(provider)
			if err != nil {
				t.Fatal(err)
			}
			module := &Module{tools: dispatcher, toolStore: store}
			// Caller supplies only the operation reference. The original contract
			// must be loaded from the durable invocation, not current registration.
			result, found, err := module.restoreBusinessTool(ctx, ToolReceiptQuery{Scope: q.Scope, Name: q.Name, CallID: q.CallID, Fingerprint: q.Fingerprint})
			if mode == "success" {
				if err != nil || !found || result["protocol"] != "mcp" {
					t.Fatal("original result did not converge", found, err)
				}
				saved, _, _ := store.LookupToolInvocation(ctx, record.ScopeHash, record.CallID)
				if saved.Status != "completed" {
					t.Fatal("known remote result not persisted")
				}
				receipt := result["receipt"].(map[string]any)
				if receipt["structuredContent"].(map[string]any)["sequence"] != json.Number("9007199254740993") {
					t.Fatal("receipt reconciliation lost integer precision")
				}
			} else {
				if found || result != nil {
					t.Fatal("unverified result accepted")
				}
				saved, _, _ := store.LookupToolInvocation(ctx, record.ScopeHash, record.CallID)
				if saved.Status != "unknown" {
					t.Fatal("negative query was treated as unsent or success")
				}
			}
			if effects.Load() != 1 || lookups.Load() > 1 {
				t.Fatal("effect replay or uncontrolled lookup retry")
			}
			if (mode == "schema-drift" || mode == "contract-drift") && lookups.Load() != 0 {
				t.Fatal("changed contract reached query tool")
			}
			if _, _, err := store.AcquireTool(leaseCtx, record.ScopeHash, record.CallID, fp, "worker-b", time.Minute); mode != "success" && !errors.Is(err, ErrToolResultUnknown) {
				t.Fatal("unknown operation was admitted again", err)
			}
			// A failed operation is local to this invocation, not a global stop.
			if _, _, err := store.AcquireTool(ctx, record.ScopeHash, "independent-step", fp, "worker-b", time.Minute); err != nil {
				t.Fatal("one failed operation blocked an independent intent", err)
			}
		})
	}
}
