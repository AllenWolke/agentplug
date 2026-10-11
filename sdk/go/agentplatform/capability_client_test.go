package agentplatform

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Verify injection through the real authenticated SDK transport, not just a helper.
// 通过真实 SDK 验签入口证明同步/异步业务接缝能调用续签客户端。
func TestExecutionServerBusinessUsesGovernedClient(t *testing.T) {
	now := time.Now()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var renewals, effects atomic.Int32
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Client-ID") != "fixture-worker" || r.Header.Get("X-Agent-Client-Secret") != strings.Repeat("w", 43) {
			t.Error("workload credentials missing")
		}
		if r.URL.Path == "/internal/context/renew" {
			old := strings.TrimPrefix(r.Header.Get("X-Platform-Context"), "Bearer ")
			claims, err := tokenClaims(old)
			if err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			claims["exp"] = now.Add(time.Minute).Unix()
			token := signToken(t, private, claims)
			renewals.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"context_token": token}})
			return
		}
		effects.Add(1)
		_, _ = w.Write([]byte(`{"data":{"text":"governed"}}`))
	}))
	defer platform.Close()
	config := CapabilityConfig{BaseURL: platform.URL, InternalToken: "internal", SigningSecret: "secret", WorkloadClientID: "fixture-worker", WorkloadClientSecret: strings.Repeat("w", 43), Now: func() time.Time { return now }}
	store := NewMemoryRunStore()
	business := func(ctx context.Context, _ ExecuteRequest) (map[string]any, error) {
		client, ok := CapabilityFromContext(ctx)
		if !ok {
			return nil, &AppError{Code: "NOT_INJECTED", Message: "client missing"}
		}
		return client.Post(ctx, "/internal/model/generate", map[string]any{"messages": []string{"question"}})
	}
	server, err := NewExecutionServer(ServerConfig{PublicKey: public, Issuer: "platform", Audience: "agent", AgentID: "agent", Capabilities: []string{"invoke", "run", "resume", "cancel", "events"}, Store: store, Capability: &config, Now: func() time.Time { return now }, Invoke: business, Run: func(ctx context.Context, r ExecuteRequest, _ EventSink, _ <-chan struct{}) (map[string]any, error) {
		return business(ctx, r)
	}})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(server.Handler())
	defer endpoint.Close()
	for _, operation := range []string{"invoke", "run"} {
		request := renewalFixtureRequest(now)
		request.Operation = operation
		request.Scope.RunID = operation + "-run"
		claims, _ := tokenClaims(request.ContextToken)
		claims["run_id"] = request.Scope.RunID
		claims["actions"] = []string{operation}
		claims["iat"] = now.Unix()
		hash, err := CanonicalBodyHash(request)
		if err != nil {
			t.Fatal(err)
		}
		claims["body_hash"] = hash
		request.ContextToken = signToken(t, private, claims)
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		path := "/internal/agent-execution/v2/invoke"
		if operation == "run" {
			path = "/internal/agent-execution/v2/runs"
		}
		httpRequest, err := http.NewRequest(http.MethodPost, endpoint.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Authorization", "Bearer "+request.ContextToken)
		response, err := http.DefaultClient.Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 200 && response.StatusCode != 202 {
			t.Fatalf("boundary rejected: %d %s", response.StatusCode, body)
		}
		if operation == "run" {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				record, _ := store.GetRun(request.Scope.RunID)
				if record.Status == "succeeded" {
					break
				}
				time.Sleep(time.Millisecond)
			}
			record, _ := store.GetRun(request.Scope.RunID)
			if record.Status != "succeeded" {
				t.Fatalf("run did not complete: %+v", record)
			}
		}
	}
	if renewals.Load() != 2 || effects.Load() != 2 {
		t.Fatalf("renewals=%d effects=%d", renewals.Load(), effects.Load())
	}
}

func renewalFixtureRequest(now time.Time) ExecuteRequest {
	policy := map[string]any{"content_hash": "hash"}
	for _, key := range []string{"model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id"} {
		policy[key] = key + "-v1"
	}
	scope := ScopeKey{TenantID: "tenant", DepartmentID: "department", ApplicationID: "app", InstallationID: "install", AgentInstanceID: "instance", AgentID: "agent", AgentVersionID: "version", PrincipalType: "user", PrincipalID: "actor", RunID: "run", SessionID: "session", TraceID: strings.Repeat("a", 32), AuthorizationEpoch: 1}
	claims := canonicalScope(scope)
	claims["sub"] = scope.PrincipalID
	claims["subject_type"] = scope.PrincipalType
	claims["iss"] = "platform"
	claims["aud"] = "agent"
	claims["actions"] = []string{"invoke"}
	claims["body_hash"] = "body"
	claims["policy_snapshot_hash"] = "hash"
	claims["execution_revision"] = 3
	claims["lease_token_hash"] = strings.Repeat("c", 64)
	claims["exp"] = now.Add(5 * time.Second).Unix()
	raw, _ := json.Marshal(claims)
	// Tests model client behavior, not token authentication; real crypto is tested
	// by the platform renewal handler. / 此处验证客户端，真实签名由平台测试覆盖。
	token := "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	return ExecuteRequest{ProtocolVersion: ProtocolVersion, ContextToken: token, Scope: scope, Operation: "invoke", Input: map[string]any{"policy_snapshot": policy}, IdempotencyKey: "request"}
}

func TestCapabilityClientConcurrentRenewalAndBusinessInjection(t *testing.T) {
	now := time.Now()
	request := renewalFixtureRequest(now)
	claims, _ := tokenClaims(request.ContextToken)
	claims["exp"] = now.Add(time.Minute).Unix()
	raw, _ := json.Marshal(claims)
	fresh := "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	var renewals, calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		proof, _ := json.Marshal([]string{"platform-capability/v2", "POST", r.URL.RequestURI(), hex.EncodeToString(digest[:])})
		mac := hmac.New(sha256.New, []byte("secret"))
		_, _ = mac.Write(proof)
		if r.Header.Get("X-Context-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("operation signature mismatch")
			w.WriteHeader(403)
			return
		}
		var envelope struct {
			Context map[string]any `json:"context"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			t.Error("invalid envelope")
			return
		}
		if envelope.Context["tenant_id"] != "tenant" || envelope.Context["actor_id"] != "actor" || envelope.Context["session_id"] != "session" || envelope.Context["installation_id"] != "install" {
			t.Error("scope projection drift")
		}
		if r.URL.Path == "/internal/context/renew" {
			renewals.Add(1)
			_, _ = w.Write([]byte(`{"data":{"context_token":"` + fresh + `"}}`))
			return
		}
		calls.Add(1)
		if r.Header.Get("X-Platform-Context") != "Bearer "+fresh {
			t.Error("old execution credential reused")
		}
		_, _ = w.Write([]byte(`{"data":{"text":"answer"}}`))
	}))
	defer server.Close()
	config := CapabilityConfig{BaseURL: server.URL, InternalToken: "internal", SigningSecret: "secret", Now: func() time.Time { return now }}
	sdkServer := ExecutionServer{cfg: ServerConfig{Capability: &config}}
	ctx, err := sdkServer.businessContext(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := CapabilityFromContext(ctx)
	if !ok {
		t.Fatal("business client not injected")
	}
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := client.Post(ctx, "/internal/model/generate", map[string]any{"messages": []string{"question"}})
			if err != nil || result["text"] != "answer" {
				t.Errorf("capability failed: %v", err)
			}
		}()
	}
	wait.Wait()
	if renewals.Load() != 1 || calls.Load() != 8 {
		t.Fatalf("renewals=%d calls=%d", renewals.Load(), calls.Load())
	}
}

func TestChildCapabilityPreservesParentAcrossRenewal(t *testing.T) {
	for _, mode := range []string{"same", "changed", "removed"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			request := renewalFixtureRequest(now)
			request.Scope.ParentRunID = "parent-root"
			claims, _ := tokenClaims(request.ContextToken)
			claims["parent_run_id"] = request.Scope.ParentRunID
			raw, _ := json.Marshal(claims)
			request.ContextToken = "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
			var renewals, calls atomic.Int32
			platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var envelope map[string]any
				if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if envelope["context"].(map[string]any)["parent_run_id"] != "parent-root" {
					t.Error("child capability lost signed parent lineage")
				}
				if r.URL.Path == "/internal/context/renew" {
					renewals.Add(1)
					next, _ := tokenClaims(strings.TrimPrefix(r.Header.Get("X-Platform-Context"), "Bearer "))
					next["exp"] = now.Add(time.Minute).Unix()
					if mode == "changed" {
						next["parent_run_id"] = "another-parent"
					} else if mode == "removed" {
						delete(next, "parent_run_id")
					}
					raw, _ := json.Marshal(next)
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"context_token": "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"}})
					return
				}
				calls.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"text": "answer"}})
			}))
			defer platform.Close()
			client, err := NewCapabilityClient(CapabilityConfig{BaseURL: platform.URL, InternalToken: "internal", SigningSecret: "secret", WorkloadClientID: "worker", WorkloadClientSecret: strings.Repeat("w", 43), Now: func() time.Time { return now }}, request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Post(context.Background(), "/internal/model/generate", map[string]any{})
			if mode == "same" {
				if err != nil || calls.Load() != 1 {
					t.Fatalf("valid lineage failed: %v calls=%d", err, calls.Load())
				}
			} else {
				var denied *AppError
				if !errors.As(err, &denied) || denied.Code != "CAPABILITY_RENEWAL_DENIED" || calls.Load() != 0 {
					t.Fatalf("changed lineage was not blocked: %v calls=%d", err, calls.Load())
				}
			}
			if renewals.Load() != 1 {
				t.Fatalf("unexpected renewals: %d", renewals.Load())
			}
		})
	}
}

func TestCapabilityRenewalFailureHasZeroCapabilityCalls(t *testing.T) {
	for _, mode := range []string{"revoked", "malformed", "changed_scope", "oversized", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			request := renewalFixtureRequest(now)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/context/renew" {
					calls.Add(1)
					w.WriteHeader(200)
					return
				}
				switch mode {
				case "revoked":
					w.WriteHeader(403)
				case "malformed":
					_, _ = w.Write([]byte("not json"))
				case "changed_scope":
					claims, _ := tokenClaims(request.ContextToken)
					claims["tenant_id"] = "other"
					claims["exp"] = now.Add(time.Minute).Unix()
					raw, _ := json.Marshal(claims)
					token := "header." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
					_, _ = w.Write([]byte(`{"data":{"context_token":"` + token + `"}}`))
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", 32769)))
				case "redirect":
					w.Header().Set("Location", "/internal/model/generate")
					w.WriteHeader(302)
				}
			}))
			defer server.Close()
			client, err := NewCapabilityClient(CapabilityConfig{BaseURL: server.URL, InternalToken: "internal", SigningSecret: "secret", Now: func() time.Time { return now }}, request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Post(context.Background(), "/internal/model/generate", map[string]any{})
			var app *AppError
			if !errors.As(err, &app) {
				t.Fatalf("unstable error: %v", err)
			}
			if calls.Load() != 0 || client.context["platform_context_token"] != request.ContextToken {
				t.Fatal("failed renewal changed identity or caused capability effect")
			}
			if (mode == "revoked" || mode == "changed_scope") && (app.Code != "CAPABILITY_RENEWAL_DENIED" || app.Retryable) {
				t.Fatalf("wrong denial classification: %+v", app)
			}
		})
	}
}

func TestCapabilityErrorsPreserveWireClassification(t *testing.T) {
	for _, test := range []struct {
		code      string
		status    int
		retryable bool
	}{
		{"CAPABILITY_RENEWAL_DENIED", 403, false},
		{"CAPABILITY_RENEWAL_UNAVAILABLE", 503, true},
		{"REQUEST_INVALID", 400, false},
	} {
		recorder := httptest.NewRecorder()
		server := ExecutionServer{}
		server.writeAppFailure(recorder, "run", &AppError{Code: test.code, Message: "safe failure", Retryable: test.retryable})
		var response ExecuteResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != test.status || response.Error == nil || response.Error.Code != test.code || response.Error.Retryable != test.retryable {
			t.Fatalf("classification lost: HTTP %d %+v", recorder.Code, response.Error)
		}
	}
}

func TestCapabilityErrorResponseDoesNotLeakUpstreamText(t *testing.T) {
	for _, test := range []struct {
		status     int
		body, code string
	}{
		{403, `{"error_code":"POLICY_DENIED","message":"sensitive upstream text"}`, "POLICY_DENIED"},
		{403, `not json with sensitive upstream text`, "CAPABILITY_DENIED"},
		{502, `{"error_code":"sensitive upstream text"}`, "CAPABILITY_RENEWAL_UNAVAILABLE"},
	} {
		now := time.Now()
		request := renewalFixtureRequest(now)
		claims, _ := tokenClaims(request.ContextToken)
		claims["exp"] = now.Add(time.Minute).Unix()
		raw, _ := json.Marshal(claims)
		request.ContextToken = "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			_, _ = w.Write([]byte(test.body))
		}))
		client, err := NewCapabilityClient(CapabilityConfig{BaseURL: server.URL, InternalToken: "internal", SigningSecret: "secret"}, request)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Post(context.Background(), "/internal/model/generate", map[string]any{})
		server.Close()
		var app *AppError
		if !errors.As(err, &app) || app.Code != test.code || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("unsafe error mapping: %v", err)
		}
	}
}
