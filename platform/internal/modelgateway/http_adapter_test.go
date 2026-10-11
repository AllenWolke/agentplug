package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
)

func TestProviderTransportMetricsUseRealHTTPOutcomesWithoutSensitiveLabels(t *testing.T) {
	readMetric := func(name string) uint64 {
		t.Helper()
		response := httptest.NewRecorder()
		telemetry.MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		for _, line := range strings.Split(response.Body.String(), "\n") {
			if strings.HasPrefix(line, name) {
				value, err := strconv.ParseUint(strings.TrimPrefix(line, name), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
		}
		t.Fatalf("missing metric %s", name)
		return 0
	}
	metric := func(result string) uint64 {
		return readMetric("agent_model_provider_transport_total{result=\"" + result + "\"} ")
	}
	beforeFailure, beforeSuccess := metric("failure"), metric("success")
	beforeInvalid := readMetric("agent_model_provider_response_invalid_total ")
	status := http.StatusServiceUnavailable
	invalid := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if invalid {
			_, _ = w.Write([]byte(`{"choices":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"approved"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/v1", nil, true)
	if _, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("provider outage was not reported: %v", err)
	}
	status = http.StatusOK
	if _, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest()); err != nil {
		t.Fatalf("provider recovery failed: %v", err)
	}
	invalid = true
	if _, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest()); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("invalid HTTP 200 model payload was accepted: %v", err)
	}
	if metric("failure") != beforeFailure+1 || metric("success") != beforeSuccess+2 ||
		readMetric("agent_model_provider_response_invalid_total ") != beforeInvalid+1 {
		t.Fatal("HTTP provider failure/recovery was not exported")
	}
	response := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, secret := range []string{testSecret, "tenant-test", "approved", "private prompt"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("provider metric exposed request data %q", secret)
		}
	}
}

const (
	testProviderID = "provider-approved"
	testModelID    = "model-approved"
	testVersionID  = "model-version-approved"
	testSecret     = "unit-test-token-never-log"
)

type testCatalog struct {
	provider ProviderMetadata
	model    ModelMetadata
	err      error
}

type testAccessResolver struct {
	selection Selection
	err       error
}

func (r testAccessResolver) ResolveModel(_ context.Context, scope sharedkernel.Scope, versionID string) (Selection, error) {
	if err := scope.ValidateTrusted(); err != nil || versionID != r.selection.ModelVersionID {
		return Selection{}, ErrModelUnavailable
	}
	return r.selection, r.err
}

func (c testCatalog) GetApprovedProvider(_ context.Context, id string) (ProviderMetadata, error) {
	if id != c.provider.ID {
		return ProviderMetadata{}, ErrProviderUnavailable
	}
	return c.provider, c.err
}
func (c testCatalog) GetApprovedModel(_ context.Context, versionID string) (ModelMetadata, error) {
	if versionID != c.model.VersionID {
		return ModelMetadata{}, ErrModelUnavailable
	}
	return c.model, c.err
}

type testSecrets map[string][]byte

func (s testSecrets) ResolveSecret(_ context.Context, reference string) ([]byte, error) {
	value, ok := s[reference]
	if !ok {
		return nil, ErrSecretUnavailable
	}
	return append([]byte(nil), value...), nil
}

type testIPResolver map[string][]net.IPAddr

func (r testIPResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r[host]
	if !ok {
		return nil, errors.New("host missing from test resolver")
	}
	return values, nil
}

func TestHTTPAdapterUsesApprovedMetadataForChatAndEmbedding(t *testing.T) {
	var chatSeen, embeddingSeen bool
	var chatWireContractValid bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			t.Errorf("expected resolved bearer secret")
		}
		if r.URL.Path == "/v1/chat/completions" {
			chatSeen = true
			body, readErr := io.ReadAll(r.Body)
			var payload map[string]json.RawMessage
			if readErr == nil && json.Unmarshal(body, &payload) == nil {
				var messages []map[string]json.RawMessage
				if json.Unmarshal(payload["messages"], &messages) == nil && len(messages) == 1 {
					var role, content string
					chatWireContractValid = json.Unmarshal(messages[0]["role"], &role) == nil &&
						json.Unmarshal(messages[0]["content"], &content) == nil &&
						role == "user" && content == "private prompt" &&
						messages[0]["Role"] == nil && messages[0]["Content"] == nil
				}
			}
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"approved answer"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`))
			return
		}
		if r.URL.Path == "/v1/embeddings" {
			embeddingSeen = true
			_, _ = w.Write([]byte(`{"data":[{"index":1,"embedding":[0.3,0.4]},{"index":0,"embedding":[0.1,0.2]}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	endpoint := server.URL + "/v1"
	adapter := newTestAdapter(t, endpoint, nil, true)

	result, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), GenerateRequest{
		ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID,
		Model: "chat-model", Messages: []Message{{Role: "user", Content: "private prompt"}}, MaxTokens: 80,
	})
	if err != nil || result.Text != "approved answer" || result.InputTokens != 7 || result.OutputTokens != 3 {
		t.Fatalf("chat response=%+v err=%v", result, err)
	}
	vectors, err := adapter.Embed(context.Background(), trustedScope(), testSnapshot(), []string{"one", "two"})
	if err != nil || len(vectors) != 2 || vectors[0][0] != 0.1 || vectors[1][0] != 0.3 || !chatSeen || !embeddingSeen || !chatWireContractValid {
		t.Fatalf("embedding response=%v err=%v chatSeen=%v embeddingSeen=%v chatWireContractValid=%v", vectors, err, chatSeen, embeddingSeen, chatWireContractValid)
	}
}

func TestHTTPAdapterFailsClosedForUnapprovedMetadataAndEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()

	catalog := testCatalog{provider: approvedProvider(server.URL), model: approvedModel()}
	catalog.model.Status = "draft"
	adapter := newTestAdapterWithCatalog(t, catalog, server.URL+"/v1", nil, true)
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), GenerateRequest{ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID, Model: "chat-model", Prompt: "hi"})
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("draft model version must fail closed: %v", err)
	}

	privateAdapter := newTestAdapter(t, "https://10.1.2.3/v1", nil, false)
	_, err = privateAdapter.Generate(context.Background(), trustedScope(), testSnapshot(), GenerateRequest{ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID, Model: "chat-model", Prompt: "hi"})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("private endpoint must be denied at dial time: %v", err)
	}

	deniedCatalog := testCatalog{provider: approvedProvider(server.URL), model: approvedModel()}
	denied := newTestAdapterWithAccessError(t, deniedCatalog, server.URL+"/v1", ErrUnsafeEndpoint)
	_, err = denied.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("policy denial must be mapped to a fail-closed result: %v", err)
	}

	resolver := testIPResolver{"model.example": {IPAddr("169.254.169.254")}}
	metadataAdapter := newTestAdapter(t, "https://model.example/v1", resolver, false)
	_, err = metadataAdapter.Generate(context.Background(), trustedScope(), testSnapshot(), GenerateRequest{ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID, Model: "chat-model", Prompt: "hi"})
	if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(strings.ToLower(err.Error()), "169.254") {
		t.Fatalf("metadata endpoint must be denied without leaking target: %v", err)
	}
}

func TestHTTPAdapterRejectsUnresolvedServiceRedirectAndOversizedResponse(t *testing.T) {
	redirectServer := httptest.NewServer(http.RedirectHandler("https://example.invalid/collect", http.StatusTemporaryRedirect))
	defer redirectServer.Close()
	redirect := newTestAdapter(t, redirectServer.URL, nil, true)
	_, err := redirect.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("redirect must be rejected without exposing details: %v", err)
	}

	largeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 2048))) }))
	defer largeServer.Close()
	large := newTestAdapter(t, largeServer.URL, nil, true)
	large.config.MaxResponseBytes = 128
	_, err = large.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response should be bounded: %v", err)
	}

	unresolved := newTestAdapter(t, "", nil, true)
	_, err = unresolved.Generate(context.Background(), trustedScope(), testSnapshot(), validRequest())
	if !errors.Is(err, ErrEndpointUnresolved) {
		t.Fatalf("unresolved service reference must fail closed: %v", err)
	}
}

func TestHTTPAdapterBoundsRequestAndNeverExposesSecret(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL, nil, true)
	adapter.config.MaxRequestBytes = 64
	request := validRequest()
	request.Prompt = strings.Repeat("p", 1024)
	_, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), request)
	if !errors.Is(err, ErrRequestTooLarge) || called || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("request limit failed or leaked data: called=%v err=%v", called, err)
	}
}

func TestMountedSecretResolverRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "mounted"), 0700); err != nil {
		t.Fatal(err)
	}
	secretRoot := filepath.Join(root, "mounted")
	if err := os.WriteFile(filepath.Join(secretRoot, "provider.key"), []byte("  token-value  \n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolver := MountedSecretResolver{Root: secretRoot, MaxBytes: 128}
	value, err := resolver.ResolveSecret(context.Background(), "secret://provider.key")
	if err != nil || string(value) != "token-value" {
		t.Fatalf("mounted secret resolve=%q err=%v", value, err)
	}
	zero(value)
	for _, ref := range []string{"secret://../outside", "secret:///absolute", "file://../../outside", "secret://sub/../provider.key"} {
		if _, err := resolver.ResolveSecret(context.Background(), ref); !errors.Is(err, ErrSecretUnavailable) {
			t.Fatalf("traversal reference %q accepted: %v", ref, err)
		}
	}
	outside := filepath.Join(root, "outside.key")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(secretRoot, "escape.key")); err != nil {
		t.Skipf("symlink creation is unavailable on this host: %v", err)
	}
	if _, err := resolver.ResolveSecret(context.Background(), "secret://escape.key"); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("symlink escape accepted: %v", err)
	}
}

func newTestAdapter(t *testing.T, endpoint string, resolver IPResolver, allowLoopback bool) *HTTPAdapter {
	t.Helper()
	return newTestAdapterWithCatalog(t, testCatalog{provider: approvedProvider(endpoint), model: approvedModel()}, endpoint, resolver, allowLoopback)
}

func newTestAdapterWithCatalog(t *testing.T, catalog testCatalog, endpoint string, resolver IPResolver, allowLoopback bool) *HTTPAdapter {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "provider.key"), []byte(testSecret), 0600); err != nil {
		t.Fatal(err)
	}
	config := HTTPConfig{SecretRoot: root, AllowLoopbackDevelopment: allowLoopback, MaxRequestBytes: 1 << 20, MaxResponseBytes: 4 << 20, AllowedHTTPSPorts: []string{"443", "8443"}, Resolver: resolver}
	access := testAccessResolver{selection: approvedSelection()}
	adapter, err := NewHTTPAdapter(config, access, catalog, catalog, MountedSecretResolver{Root: root}, StaticEndpointResolver{"service://approved-model-provider": endpoint})
	if err != nil {
		t.Fatalf("construct model HTTP adapter: %v", err)
	}
	// The test metadata refers to a mounted credential; production resolution is path-confined by MountedSecretResolver.
	adapter.secrets = MountedSecretResolver{Root: root}
	return adapter
}

func newTestAdapterWithAccessError(t *testing.T, catalog testCatalog, endpoint string, accessErr error) *HTTPAdapter {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "provider.key"), []byte(testSecret), 0600); err != nil {
		t.Fatal(err)
	}
	config := HTTPConfig{SecretRoot: root, AllowLoopbackDevelopment: true}
	adapter, err := NewHTTPAdapter(config, testAccessResolver{selection: approvedSelection(), err: accessErr}, catalog, catalog, MountedSecretResolver{Root: root}, StaticEndpointResolver{"service://approved-model-provider": endpoint})
	if err != nil {
		t.Fatalf("construct model HTTP adapter: %v", err)
	}
	return adapter
}

func approvedProvider(_ string) ProviderMetadata {
	return ProviderMetadata{ID: testProviderID, Key: "local-provider", TrustZone: "local", EndpointRef: "service://approved-model-provider", SecretRef: "secret://provider.key", Status: "approved"}
}

func approvedModel() ModelMetadata {
	return ModelMetadata{ID: testModelID, VersionID: testVersionID, ProviderID: testProviderID, Key: "chat-model", Status: "approved"}
}

func approvedSelection() Selection {
	return Selection{ModelVersionID: testVersionID, ProviderID: testProviderID, ProviderKey: "local-provider", ModelID: testModelID, ModelKey: "chat-model", TrustZone: "local", DeploymentID: "deployment-test", EndpointRef: "service://approved-model-provider", CapacityUnits: 2}
}

func testSnapshot() policyasset.Snapshot {
	return policyasset.Snapshot{Model: policyasset.ModelPolicy{Provider: "local-provider", Model: "chat-model", ModelVersionID: testVersionID}}
}

func trustedScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentInstanceID: "instance-a", AgentID: "agent-a", PrincipalID: "user-a", PrincipalType: "user", InstallationID: "installation-a", AgentVersionID: "agent-v1", SessionID: "session-a", RunID: "run-a", AuthorizationEpoch: 1, TraceID: "trace-a"}
}

func validRequest() GenerateRequest {
	return GenerateRequest{ModelVersionID: testVersionID, ProviderID: testProviderID, ModelID: testModelID, Model: "chat-model", Messages: []Message{{Role: "user", Content: "hello"}}, MaxTokens: 100}
}

func IPAddr(value string) net.IPAddr {
	parsed := net.ParseIP(value)
	if parsed == nil {
		panic("invalid hard-coded test IP")
	}
	return net.IPAddr{IP: parsed}
}
