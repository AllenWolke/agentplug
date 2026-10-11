package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"generated-agent/platform_entry/agentplatform"
)

// sharedFixture is signed once by the Go SDK. Verifying it and recomputing the
// same body hash proves this generated Agent agrees with the platform and with
// the Python/Java templates byte for byte.
// sharedFixture 由 Go SDK 一次性签名。校验它并重算同一正文哈希，即证明该生成 Agent
// 与平台、以及与 Python/Java 模板逐字节一致。
type sharedFixture struct {
	Issuer       string         `json:"issuer"`
	Audience     string         `json:"audience"`
	Now          int64          `json:"now"`
	PublicKeyB64 string         `json:"public_key_b64"`
	BodyHash     string         `json:"body_hash"`
	Token        string         `json:"token"`
	Request      map[string]any `json:"request"`
}

func loadSharedFixture(t *testing.T) sharedFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "fixtures", "execution-v2-capability.json"))
	if os.IsNotExist(err) {
		// A standalone generated project has no monorepo sibling, so the shared
		// cross-language fixture is simply absent; lifecycle tests still mint
		// their own keys and cover the security seam end to end.
		// 独立生成的项目没有 monorepo 兄弟目录，共享跨语言 fixture 自然缺失；
		// 生命周期测试会自铸密钥，端到端覆盖安全接缝。
		t.Skip("shared capability fixture not present (standalone generated project)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var fixture sharedFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureKey(t *testing.T) (sharedFixture, ed25519.PublicKey) {
	t.Helper()
	fixture := loadSharedFixture(t)
	raw, err := base64.StdEncoding.DecodeString(fixture.PublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("fixture public key did not decode to an Ed25519 public key: %v", err)
	}
	return fixture, ed25519.PublicKey(raw)
}

func fixtureRequest(t *testing.T, fixture sharedFixture) agentplatform.ExecuteRequest {
	t.Helper()
	raw, err := json.Marshal(fixture.Request)
	if err != nil {
		t.Fatal(err)
	}
	var request agentplatform.ExecuteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func cloneRequest(request agentplatform.ExecuteRequest) agentplatform.ExecuteRequest {
	clone := request
	clone.Input = map[string]any{}
	for key, value := range request.Input {
		clone.Input[key] = value
	}
	return clone
}

// newFixtureBackedServer wires the template's real Eino graph behind the SDK
// transport with the shared fixture's verification material.
// newFixtureBackedServer 用共享 fixture 的校验材料，把模板真实的 Eino 图接入
// SDK 传输层。
func newFixtureBackedServer(t *testing.T, fixture sharedFixture, key ed25519.PublicKey) *agentplatform.ExecutionServer {
	t.Helper()
	t.Setenv("AGENT_PLATFORM_ISSUER", fixture.Issuer)
	t.Setenv("AGENT_PLATFORM_AUDIENCE", fixture.Audience)
	graph, err := NewEchoGraph(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	server, err := newExecutionServer(key, fixture.Audience, agentplatform.NoopTracer(), graph, func() time.Time { return time.Unix(fixture.Now, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestSharedCapabilityFixtureVerifiesAndMatchesCanonicalHash(t *testing.T) {
	fixture, key := fixtureKey(t)
	request := fixtureRequest(t, fixture)

	hash, err := agentplatform.CanonicalBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	if hash != fixture.BodyHash {
		t.Fatalf("canonical body hash drifted from the SDK fixture: got %s want %s", hash, fixture.BodyHash)
	}
	now := time.Unix(fixture.Now, 0).UTC()
	if _, err := agentplatform.VerifyContext(request, key, fixture.Issuer, fixture.Audience, now); err != nil {
		t.Fatalf("a Gateway-signed capability was rejected: %v", err)
	}
}

func TestForgedTamperedAndMisScopedCapabilitiesAreRejected(t *testing.T) {
	fixture, key := fixtureKey(t)
	request := fixtureRequest(t, fixture)
	now := time.Unix(fixture.Now, 0).UTC()

	cases := map[string]func(*agentplatform.ExecuteRequest){
		"tampered signature": func(r *agentplatform.ExecuteRequest) {
			parts := strings.Split(r.ContextToken, ".")
			r.ContextToken = parts[0] + "." + parts[1] + "." + strings.Repeat("A", 86)
		},
		"length-only token":       func(r *agentplatform.ExecuteRequest) { r.ContextToken = "0123456789abcdef0123456789abcdef" },
		"tampered body":           func(r *agentplatform.ExecuteRequest) { r.Input["injected"] = "value" },
		"tampered idempotency":    func(r *agentplatform.ExecuteRequest) { r.IdempotencyKey = "other-key" },
		"missing policy snapshot": func(r *agentplatform.ExecuteRequest) { delete(r.Input, "policy_snapshot") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := cloneRequest(request)
			mutate(&candidate)
			if _, err := agentplatform.VerifyContext(candidate, key, fixture.Issuer, fixture.Audience, now); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}

	t.Run("wrong audience", func(t *testing.T) {
		if _, err := agentplatform.VerifyContext(request, key, fixture.Issuer, "another-agent", now); err == nil {
			t.Fatal("a capability for another audience was accepted")
		}
	})

	t.Run("expired lifetime", func(t *testing.T) {
		late := time.Unix(fixture.Now+3600, 0).UTC()
		if _, err := agentplatform.VerifyContext(request, key, fixture.Issuer, fixture.Audience, late); err == nil {
			t.Fatal("an expired capability was accepted")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		if _, err := agentplatform.VerifyContext(request, key, "somewhere-else", fixture.Audience, now); err == nil {
			t.Fatal("a capability from another issuer was accepted")
		}
	})
}

func TestVerifierRefusesToStartWithoutPlatformMaterial(t *testing.T) {
	t.Setenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64", "")
	t.Setenv("PLATFORM_CONTEXT_PUBLIC_KEY", "")
	t.Setenv("AGENT_PLATFORM_PUBLIC_KEY_FILE", "")
	t.Setenv("PLATFORM_CONTEXT_PUBLIC_KEY_FILE", "")
	if _, err := publicKeyFromEnv(); err == nil {
		t.Fatal("the verifier was built without platform verification material")
	}
}

func TestVerifierAcceptsThePlatformSecretKeyForm(t *testing.T) {
	fixture := loadSharedFixture(t)
	t.Setenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64", "")
	t.Setenv("PLATFORM_CONTEXT_PUBLIC_KEY", fixture.PublicKeyB64)
	key, err := publicKeyFromEnv()
	if err != nil {
		t.Fatalf("the platform secret form of the key was rejected: %v", err)
	}
	if len(key) != ed25519.PublicKeySize {
		t.Fatal("the platform secret key did not decode to an Ed25519 public key")
	}
	if issuer, audience := issuerFromEnv(), audienceFromEnv(); issuer != "platform-runtime-gateway" || audience != defaultPlatformAudience {
		t.Fatalf("defaults: issuer=%q audience=%q", issuer, audience)
	}
}

func TestHandlerRejectsUnverifiedCallerBeforeTheEinoSeam(t *testing.T) {
	fixture, key := fixtureKey(t)
	request := fixtureRequest(t, fixture)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	server := newFixtureBackedServer(t, fixture, key)
	post := func(raw []byte, token string) *httptest.ResponseRecorder {
		httpRequest := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/invoke", bytes.NewReader(raw))
		if token != "" {
			httpRequest.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httpRequest)
		return response
	}

	if response := post(body, fixture.Token); response.Code != 200 {
		t.Fatalf("a Gateway-signed call was rejected: %d %s", response.Code, response.Body.String())
	}
	var accepted agentplatform.ExecuteResponse
	if err := json.Unmarshal(post(body, fixture.Token).Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Output["framework"] != "eino" || accepted.Output["run_id"] != "conformance-run" || accepted.Output["tenant_id"] != "tenant-a" {
		t.Fatalf("the Eino graph did not observe the verified platform context: %v", accepted.Output)
	}
	if response := post(body, ""); response.Code != 401 {
		t.Fatalf("a caller without a bearer credential got %d", response.Code)
	}
	if response := post(body, "0123456789abcdef0123456789abcdef"); response.Code != 401 {
		t.Fatalf("a length-only capability got %d", response.Code)
	}
	forgedBody, err := json.Marshal(map[string]any{
		"protocol_version": "agent-execution/v2", "context_token": "0123456789abcdef0123456789abcdef",
		"scope": fixture.Request["scope"], "operation": "invoke", "idempotency_key": "conformance-invoke",
		"input_schema": "schema://example/input/v1", "input": fixture.Request["input"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := post(forgedBody, "0123456789abcdef0123456789abcdef"); response.Code != 401 {
		t.Fatalf("a forged capability got %d", response.Code)
	}
	malformed, err := json.Marshal(map[string]any{"protocol_version": "agent-execution/v2", "unknown": 1})
	if err != nil {
		t.Fatal(err)
	}
	if response := post(malformed, fixture.Token); response.Code != 400 {
		t.Fatalf("a malformed envelope got %d", response.Code)
	}
}
