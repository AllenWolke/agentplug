package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func TestSDKTransportSignsBusinessCapabilitiesAndRejectsTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	f := &capabilityFixture{}
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(raw)
		proof, _ := json.Marshal([]string{"platform-capability/v2", r.Method, r.URL.RequestURI(), hex.EncodeToString(digest[:])})
		mac := hmac.New(sha256.New, []byte("test-signing-secret"))
		_, _ = mac.Write(proof)
		if r.Header.Get("X-Context-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || r.Header.Get("X-Agent-Client-ID") != "test-machine" || r.Header.Get("X-Agent-Client-Secret") != "01234567890123456789012345678901" || r.Header.Get("X-Internal-Token") != "test-internal" {
			t.Error("missing actual SDK signature or workload proof")
			http.Error(w, "denied", 403)
			return
		}
		var envelope struct {
			Context map[string]any `json:"context"`
			Input   map[string]any `json:"input"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.Context["actor_id"] != "demo.go.user" || envelope.Context["task_id"] != "run-1" {
			t.Error("scope was not propagated")
			http.Error(w, "invalid", 400)
			return
		}
		if r.Header.Get("X-Trace-ID") != envelope.Context["trace_id"] {
			t.Error("trace context was not propagated")
			http.Error(w, "invalid trace", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var result map[string]any
		var err error
		if r.URL.Path == "/internal/context/renew" {
			result = map[string]any{"context_token": envelope.Context["platform_context_token"]}
		} else {
			result, err = f.Post(r.Context(), r.URL.Path, envelope.Input)
		}
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": result})
	}))
	defer platform.Close()
	server, err := agentplatform.NewExecutionServer(agentplatform.ServerConfig{PublicKey: public, Issuer: "platform-runtime-gateway", Audience: "example-go-operations", AgentID: "example-go-operations", Capabilities: []string{"invoke"}, Store: agentplatform.NewMemoryRunStore(), Invoke: invokeBusiness, Capability: &agentplatform.CapabilityConfig{BaseURL: platform.URL, InternalToken: "test-internal", SigningSecret: "test-signing-secret", WorkloadClientID: "test-machine", WorkloadClientSecret: "01234567890123456789012345678901"}})
	if err != nil {
		t.Fatal(err)
	}
	r := businessRequest()
	r.ProtocolVersion = agentplatform.ProtocolVersion
	r.Operation = "invoke"
	r.Scope = agentplatform.ScopeKey{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "example-go-operations", AgentInstanceID: "instance", InstallationID: "installation", AgentVersionID: "version", PrincipalType: "human", PrincipalID: "demo.go.user", SessionID: "session", RunID: "run-1", AuthorizationEpoch: 1, TraceID: "trace"}
	r.Input["policy_snapshot"] = map[string]any{"content_hash": "policy-hash", "model_profile_id": "model", "prompt_version_id": "prompt", "tool_policy_id": "tool", "memory_policy_id": "memory", "knowledge_policy_id": "knowledge", "runtime_policy_id": "runtime"}
	hash, err := agentplatform.CanonicalBodyHash(r)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "platform-runtime-gateway", "aud": "example-go-operations", "subject_type": "human", "sub": "demo.go.user", "tenant_id": "tenant", "department_id": "department", "application_id": "application", "agent_id": "example-go-operations", "agent_instance_id": "instance", "agent_version_id": "version", "installation_id": "installation", "run_id": "run-1", "session_id": "session", "trace_id": "trace", "lease_token_hash": strings.Repeat("c", 64), "authorization_epoch": 1, "actions": []string{"invoke"}, "policy_snapshot_hash": "policy-hash", "body_hash": hash, "execution_revision": 1, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA"})
	payload, _ := json.Marshal(claims)
	prefix := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	r.ContextToken = prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(prefix)))
	post := func(request agentplatform.ExecuteRequest) *httptest.ResponseRecorder {
		body, _ := json.Marshal(request)
		httpRequest := httptest.NewRequest("POST", "/internal/agent-execution/v2/invoke", bytes.NewReader(body))
		httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, httpRequest)
		return w
	}
	w := post(r)
	if w.Code != 200 {
		t.Fatalf("signed business invoke rejected: %d %s", w.Code, w.Body.String())
	}
	mu.Lock()
	count := len(f.paths)
	mu.Unlock()
	mu.Lock()
	required := map[string]int{
		"/internal/runtime/harness-policy": 1,
		"/internal/context/prepare":        1,
		"/internal/prompt/resolve":         1,
		"/internal/skill/load":             1,
		"/internal/tool/invoke":            1,
		"/internal/knowledge/search":       1,
		"/internal/model/generate":         1,
		"/internal/memory/access":          2,
		"/internal/state/checkpoint":       2,
	}
	for path, minimum := range required {
		found := 0
		for _, got := range f.paths {
			if got == path {
				found++
			}
		}
		if found < minimum {
			mu.Unlock()
			t.Fatalf("expected %d %s calls, got %d (%v)", minimum, path, found, f.paths)
		}
	}
	mu.Unlock()
	r.Scope.PrincipalID = "other-user"
	w = post(r)
	if w.Code != 401 {
		t.Fatalf("tampered identity accepted: %d", w.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(f.paths) != count {
		t.Fatal("tampered request reached platform capabilities")
	}
}
