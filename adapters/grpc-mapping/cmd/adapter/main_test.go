package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/grpc-mapping-adapter/internal/descriptor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/test/bufconn"
)

const (
	testService = "grpc.demo.Agent"
	testMethod  = "Invoke"
	testHash    = "published-hash"
	testIssuer  = "platform"
)

func TestMain(m *testing.M) {
	encoding.RegisterCodec(jsonCodec{})
	os.Exit(m.Run())
}

func newAdapter(t *testing.T, conn *grpc.ClientConn) (*adapter, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &adapter{desc: descriptor.Descriptor{AdapterID: "grpc-agent", Service: testService, Method: testMethod, MappingHash: testHash, Revision: 1}, key: public, issuer: testIssuer, conn: conn, now: func() time.Time { return time.Now().UTC() }}
	return a, private
}

func requestInput() map[string]any {
	return map[string]any{
		"question":        "q",
		"policy_snapshot": map[string]any{"content_hash": "snapshot-hash"},
		"mapping_plan":    map[string]any{"mapping_id": "grpc-demo", "version": "1.0.0", "hash": testHash},
	}
}

func signedRequest(t *testing.T, private ed25519.PrivateKey, operation string, input map[string]any) agentplatform.ExecuteRequest {
	t.Helper()
	now := time.Now().UTC()
	request := agentplatform.ExecuteRequest{
		ProtocolVersion: protocolVersion,
		Operation:       operation,
		IdempotencyKey:  "idem-key",
		InputSchema:     "schema://grpc-agent/input/v1",
		Input:           input,
		Scope:           agentplatform.ScopeKey{TenantID: "t", ApplicationID: "a", AgentInstanceID: "i", InstallationID: "install-1", PrincipalType: "user", PrincipalID: "u", RunID: "run-1", AuthorizationEpoch: 1},
	}
	hash, err := agentplatform.CanonicalBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": testIssuer, "aud": "agent-runtime", "subject_type": "user", "sub": "u", "tenant_id": "t", "application_id": "a", "agent_instance_id": "i", "installation_id": "install-1", "authorization_epoch": 1, "actions": []string{"invoke"}, "policy_snapshot_hash": "snapshot-hash", "body_hash": hash, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	h, p := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload)
	request.ContextToken = h + "." + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(h+"."+p)))
	return request
}

func invokeRaw(t *testing.T, a *adapter, body string, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/internal/agent-execution/v2/invoke", bytes.NewReader([]byte(body)))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	a.routes().ServeHTTP(recorder, request)
	return recorder
}

func invoke(t *testing.T, a *adapter, request any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return invokeRaw(t, a, string(body), bearer)
}

func startUpstream(t *testing.T) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: testService,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: testMethod,
			Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var request map[string]any
				if err := dec(&request); err != nil {
					return nil, err
				}
				return map[string]any{"answer": request["question"]}, nil
			},
		}},
	}, struct{}{})
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.CallContentSubtype(codecName)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); server.Stop(); _ = listener.Close() })
	return conn
}

func has(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestManifestEndpoint(t *testing.T) {
	a, _ := newAdapter(t, nil)
	recorder := httptest.NewRecorder()
	a.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/agent-manifest.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var manifest struct {
		ManifestVersion    string            `json:"manifest_version"`
		ExecutionProtocols []string          `json:"execution_protocols"`
		Capabilities       []string          `json:"capabilities"`
		Runtime            map[string]string `json:"runtime"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ManifestVersion != "agent-manifest/v1" || !has(manifest.ExecutionProtocols, protocolVersion) || !has(manifest.Capabilities, "invoke") || manifest.Runtime["transport"] != "grpc" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestInvokeRejectsMalformedContract(t *testing.T) {
	a, _ := newAdapter(t, nil)
	bodies := []string{
		`{`,
		`{}`,
		`{"protocol_version":"agent-execution/v2","scope":{"run_id":"run-1"}}`,
		`{"protocol_version":"agent-execution/v2","operation":"run","scope":{"run_id":"run-1"}}`,
		`{"protocol_version":"agent-execution/v2","operation":"invoke"}`,
	}
	for _, body := range bodies {
		if recorder := invokeRaw(t, a, body, ""); recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("body %s => status %d, want 422", body, recorder.Code)
		}
	}
}

func TestInvokeRejectsBadToken(t *testing.T) {
	a, private := newAdapter(t, nil)
	valid := signedRequest(t, private, "invoke", requestInput())
	if recorder := invoke(t, a, valid, ""); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer => status %d, want 401", recorder.Code)
	}
	if recorder := invoke(t, a, valid, "wrong"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched bearer => status %d, want 401", recorder.Code)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := signedRequest(t, attacker, "invoke", requestInput())
	if recorder := invoke(t, a, forged, forged.ContextToken); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("forged token => status %d, want 401", recorder.Code)
	}
}

func TestInvokeRejectsMappingHashMismatch(t *testing.T) {
	a, private := newAdapter(t, nil)
	mismatchInput := requestInput()
	mismatchInput["mapping_plan"] = map[string]any{"mapping_id": "grpc-demo", "version": "1.0.0", "hash": "tampered"}
	mismatch := signedRequest(t, private, "invoke", mismatchInput)
	if recorder := invoke(t, a, mismatch, mismatch.ContextToken); recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("hash mismatch => status %d, want 422", recorder.Code)
	}
	missingInput := requestInput()
	delete(missingInput, "mapping_plan")
	missing := signedRequest(t, private, "invoke", missingInput)
	if recorder := invoke(t, a, missing, missing.ContextToken); recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing plan => status %d, want 422", recorder.Code)
	}
}

func TestInvokeHappyPath(t *testing.T) {
	conn := startUpstream(t)
	a, private := newAdapter(t, conn)
	request := signedRequest(t, private, "invoke", requestInput())
	recorder := invoke(t, a, request, request.ContextToken)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		ProtocolVersion string         `json:"protocol_version"`
		RunID           string         `json:"run_id"`
		Status          string         `json:"status"`
		OutputSchema    string         `json:"output_schema"`
		Output          map[string]any `json:"output"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != protocolVersion || response.RunID != "run-1" || response.Status != "succeeded" || response.OutputSchema != "schema://grpc-agent/output/v1" || response.Output["answer"] != "q" {
		t.Fatalf("unexpected response: %+v", response)
	}
}
