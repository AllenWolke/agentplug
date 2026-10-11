package agentplatform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestDeclaredManifestValidatedAndFrozen(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	declaration := map[string]any{
		"manifest_version": "agent-manifest/v1", "agent_id": "test-agent", "version": "0.1.1",
		"execution_protocols": []string{ProtocolVersion}, "capabilities": []string{"invoke"},
		"schemas":  map[string]string{"input": "schema://test-agent/input/v1", "output": "schema://test-agent/output/v1"},
		"runtime":  map[string]string{"transport": "http", "isolation": "container", "health_path": "/health/ready", "run_store": "memory-dev-only(L2/L3 forbidden)"},
		"metadata": map[string]string{"business": "demonstration"},
	}
	cfg := ServerConfig{PublicKey: key, Issuer: "platform", Audience: "runtime", AgentID: "test-agent", AgentVersion: "0.1.1", Capabilities: []string{"invoke"}, Store: NewMemoryRunStore(), Invoke: func(context.Context, ExecuteRequest) (map[string]any, error) { return nil, nil }}
	for _, mutation := range []string{"valid", "valid-v2", "identity", "version", "capabilities", "durability", "foreign-schema", "zero-schema", "leading-zero-schema", "query-schema", "fragment-schema", "path-schema"} {
		t.Run(mutation, func(t *testing.T) {
			raw, _ := json.Marshal(declaration)
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			switch mutation {
			case "valid-v2":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v2"
				changed["schemas"].(map[string]any)["output"] = "schema://test-agent/output/v2"
			case "foreign-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://other-agent/input/v2"
			case "zero-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v0"
			case "leading-zero-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v02"
			case "query-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v2?x=1"
			case "fragment-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v2#x"
			case "path-schema":
				changed["schemas"].(map[string]any)["input"] = "schema://test-agent/input/v2/extra"
			case "identity":
				changed["agent_id"] = "other-agent"
			case "version":
				changed["version"] = "0.0.0"
			case "capabilities":
				changed["capabilities"] = []string{"invoke", "run"}
			case "durability":
				changed["runtime"].(map[string]any)["run_store"] = "durable"
			}
			cfg.Manifest, _ = json.Marshal(changed)
			server, err := NewExecutionServer(cfg)
			if mutation != "valid" && mutation != "valid-v2" {
				if err == nil {
					t.Fatal("inconsistent declaration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg.Manifest[0] = '!'
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/.well-known/agent-manifest.json", nil))
			var served map[string]any
			if json.Unmarshal(response.Body.Bytes(), &served) != nil || served["agent_id"] != "test-agent" || served["metadata"] == nil {
				t.Fatal("published declaration lost or mutated")
			}
		})
	}
}
