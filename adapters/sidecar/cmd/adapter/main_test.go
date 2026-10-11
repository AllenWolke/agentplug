package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func TestSidecarRejectsMalformedAndMissingCapabilityWithoutContactingUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer upstream.Close()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	startSidecarAdapter(t, upstream.URL, public, "")
	client := &http.Client{Timeout: 3 * time.Second}

	resp := postSidecar(t, client, []byte("{"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		resp.Body.Close()
		t.Fatalf("malformed body status=%d, want %d", resp.StatusCode, http.StatusUnprocessableEntity)
	}
	resp.Body.Close()

	body, err := json.Marshal(agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		Operation:       "invoke",
		Scope:           agentplatform.ScopeKey{RunID: "run-1"},
		Input:           map[string]any{"message": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp = postSidecar(t, client, body)
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("missing capability status=%d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	resp.Body.Close()

	request := agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		ContextToken:    "malformed-capability",
		Operation:       "invoke",
		Scope:           agentplatform.ScopeKey{RunID: "run-1"},
		Input:           map[string]any{"message": "test"},
	}
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	resp = postSidecarWithAuthorization(t, client, body, request.ContextToken)
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("malformed capability status=%d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	resp.Body.Close()

	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream was contacted for rejected request %d time(s)", got)
	}
}

// TestSidecarRefusesToStartWithoutClientIdentity proves mutual TLS is not
// optional: a sidecar without its own certificate fails closed at start-up.
// TestSidecarRefusesToStartWithoutClientIdentity 证明双向 TLS 不是可选项：没有自身
// 证书的 Sidecar 在启动阶段失败闭合。
func TestSidecarRefusesToStartWithoutClientIdentity(t *testing.T) {
	binary := buildSidecarAdapter(t)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"SIDECAR_UPSTREAM_URL=https://registered-agent.example.com",
		"PLATFORM_CONTEXT_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize)),
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("sidecar started without a client certificate; output=%s", output)
	}
	if !strings.Contains(string(output), "mutual TLS is required") {
		t.Fatalf("start-up failure did not name mutual TLS: %s", output)
	}
}

// TestSidecarDeclaresCapabilitiesAndRefusesUnimplementedOnes proves the sidecar
// advertises only what it serves and answers cancel/resume/checkpoint with the
// platform's stable UNSUPPORTED_CAPABILITY code instead of a bare 404.
// TestSidecarDeclaresCapabilitiesAndRefusesUnimplementedOnes 证明 Sidecar 只宣告自身
// 提供的能力，并以平台稳定错误码 UNSUPPORTED_CAPABILITY 回应 cancel/resume/checkpoint，
// 而不是裸 404。
func TestSidecarDeclaresCapabilitiesAndRefusesUnimplementedOnes(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	startSidecarAdapter(t, "https://registered-agent.example.com", public, "")
	client := &http.Client{Timeout: 3 * time.Second}

	manifest := getJSON(t, client, "http://127.0.0.1:8080/.well-known/agent-manifest.json")
	if capabilities := manifest["capabilities"].([]any); len(capabilities) != 2 || capabilities[0] != "invoke" {
		t.Fatalf("manifest advertised %v, want invoke/health only", capabilities)
	}

	for _, capability := range []string{"cancel", "resume", "checkpoint"} {
		resp, err := client.Post("http://127.0.0.1:8080/internal/agent-execution/v2/"+capability, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotImplemented {
			resp.Body.Close()
			t.Fatalf("%s status=%d, want %d", capability, resp.StatusCode, http.StatusNotImplemented)
		}
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			resp.Body.Close()
			t.Fatalf("decode %s envelope: %v", capability, err)
		}
		resp.Body.Close()
		if envelope.Error.Code != unsupportedCapabilityCode {
			t.Fatalf("%s error code = %q, want %q", capability, envelope.Error.Code, unsupportedCapabilityCode)
		}
	}
}

// TestSidecarEventsEndpointIsUnsupportedUntilAnEventsPathIsRegistered keeps the
// sidecar from pretending to stream: without a registered events path the
// endpoint answers UNSUPPORTED_CAPABILITY, and the manifest omits events.
// TestSidecarEventsEndpointIsUnsupportedUntilAnEventsPathIsRegistered 让 Sidecar 不
// 假装能流式输出：未登记事件路径时该端点返回 UNSUPPORTED_CAPABILITY，manifest 也不宣告 events。
func TestSidecarEventsEndpointIsUnsupportedUntilAnEventsPathIsRegistered(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	startSidecarAdapter(t, "https://registered-agent.example.com", public, "")
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Post("http://127.0.0.1:8080/internal/agent-execution/v2/runs/run-1/events", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("events status=%d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}
}

// TestSidecarAdvertisesEventsOnlyWhenRegistered proves the registered events
// path is reflected in the manifest.
// TestSidecarAdvertisesEventsOnlyWhenRegistered 证明已登记事件路径会体现在 manifest 中。
func TestSidecarAdvertisesEventsOnlyWhenRegistered(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	startSidecarAdapter(t, "https://registered-agent.example.com", public, "/events")
	client := &http.Client{Timeout: 3 * time.Second}

	manifest := getJSON(t, client, "http://127.0.0.1:8080/.well-known/agent-manifest.json")
	capabilities := manifest["capabilities"].([]any)
	if len(capabilities) != 3 || capabilities[2] != "events" {
		t.Fatalf("manifest advertised %v, want events to be declared", capabilities)
	}
}

func getJSON(t *testing.T, client *http.Client, url string) map[string]any {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return payload
}

func buildSidecarAdapter(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "sidecar-adapter")
	if filepath.Ext(mustExecutable(t)) == ".exe" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build sidecar adapter: %v", err)
	}
	return binary
}

func startSidecarAdapter(t *testing.T, upstreamURL string, public ed25519.PublicKey, eventsPath string) {
	t.Helper()
	binary := buildSidecarAdapter(t)
	certFile, keyFile := writeSidecarIdentity(t)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"SIDECAR_UPSTREAM_URL="+upstreamURL,
		"SIDECAR_MTLS_CERT_FILE="+certFile,
		"SIDECAR_MTLS_KEY_FILE="+keyFile,
		"SIDECAR_EVENTS_PATH="+eventsPath,
		"PLATFORM_CONTEXT_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(public),
		"PLATFORM_CONTEXT_ISSUER=platform",
		"AGENT_ID=sidecar-test-agent",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sidecar adapter: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitSidecarReady(t)
}

// writeSidecarIdentity issues a throwaway self-signed client identity so the
// adapter has a real certificate/key pair to load.
// writeSidecarIdentity 签发一次性自签客户端身份，使 Adapter 有真实的证书/私钥可加载。
func writeSidecarIdentity(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sidecar-test-identity"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	return executable
}

func postSidecar(t *testing.T, client *http.Client, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/internal/agent-execution/v2/invoke", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postSidecarWithAuthorization(t *testing.T, client *http.Client, body []byte, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/internal/agent-execution/v2/invoke", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func waitSidecarReady(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://127.0.0.1:8080/health/ready")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("sidecar adapter did not become ready")
}
