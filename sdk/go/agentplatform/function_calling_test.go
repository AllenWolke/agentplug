package agentplatform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFunctionLoopUsesPublishedBindingStableKeysAndNoImplicitApproval(t *testing.T) {
	now := time.Now()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	request := renewalFixtureRequest(now)
	claims, _ := tokenClaims(request.ContextToken)
	claims["exp"] = now.Add(time.Minute).Unix()
	request.ContextToken = signToken(t, private, claims)
	var keys []string
	toolEffects := 0
	modelCalls := 0
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input map[string]any `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("bad request")
		}
		if r.Header.Get("X-Context-Signature") == "" || r.Header.Get("X-Platform-Context") == "" {
			t.Error("unsigned SDK call")
		}
		if r.URL.Path == "/internal/tool/invoke" {
			toolEffects++
			if body.Input["name"] != "runtime.inspect" || body.Input["confirmed"] != false {
				t.Error("tool authority escalated")
			}
			keys = append(keys, body.Input["call_id"].(string))
			if toolEffects == 2 {
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"raw_output": "excluded-original-body"}, "observation": map[string]any{"version": "runtime-observation/v1", "tool_name": "runtime.inspect", "call_id": body.Input["call_id"], "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data", "context_output": map[string]any{"healthy": true}}}})
				return
			}
			_, _ = w.Write([]byte(`{"data":{"data":{"healthy":true}}}`))
			return
		}
		modelCalls++
		keys = append(keys, body.Input["idempotency_key"].(string))
		if modelCalls%2 == 1 {
			_, _ = w.Write([]byte(`{"data":{"text":"","completion_status":"tool_calls","function_bindings":{"inspect":"runtime.inspect"},"tool_calls":[{"id":"call-1","type":"function","function":{"name":"inspect","arguments":"{}"}}]}}`))
		} else {
			messages := body.Input["messages"].([]any)
			if len(messages) != 3 || messages[2].(map[string]any)["tool_call_id"] != "call-1" {
				t.Error("tool transcript missing")
			}
			if modelCalls == 4 {
				content := messages[2].(map[string]any)["content"].(string)
				if strings.Contains(content, "excluded-original-body") || !strings.Contains(content, "context_output") {
					t.Error("model received unbounded original tool result")
				}
			}
			_, _ = w.Write([]byte(`{"data":{"text":"ready","finish_reason":"stop"}}`))
		}
	}))
	defer platform.Close()
	client, err := NewCapabilityClient(CapabilityConfig{BaseURL: platform.URL, InternalToken: "internal", SigningSecret: "secret", Now: func() time.Time { return now }}, request)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "inspect"}}, "function_names": []string{"inspect"}, "idempotency_key": "stable"}
	for i := 0; i < 2; i++ {
		result, err := client.GenerateWithFunctions(context.Background(), input, 2)
		if err != nil || result["text"] != "ready" {
			t.Fatalf("function loop failed %+v %v", result, err)
		}
	}
	if toolEffects != 2 || len(keys) != 6 || keys[0] != keys[3] || keys[1] != keys[4] || keys[2] != keys[5] || keys[0] == keys[2] {
		t.Fatal("unstable or duplicate phase identities")
	}
	if len(input["messages"].([]any)) != 1 || input["idempotency_key"] != "stable" {
		t.Fatal("input mutated")
	}
}

func TestFunctionToolObservationRejectsUnknownMismatchedOrOversizedContext(t *testing.T) {
	base := map[string]any{"version": "runtime-observation/v1", "tool_name": "runtime.inspect", "call_id": "call", "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data", "context_output": map[string]any{"healthy": true}}
	for _, change := range []func(map[string]any){func(o map[string]any) { o["effect"] = "unknown" }, func(o map[string]any) { o["call_id"] = "other" }, func(o map[string]any) { o["context_output"] = strings.Repeat("x", 2049) }, func(o map[string]any) { o["instruction_trust"] = "system" }} {
		o := map[string]any{}
		for key, value := range base {
			o[key] = value
		}
		change(o)
		if _, err := functionToolContext(map[string]any{"observation": o}, "runtime.inspect", "call"); err == nil {
			t.Fatal("unsafe observation entered model transcript")
		}
	}
}
