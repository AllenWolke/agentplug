package adaptergen

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func buildGeneratedProxy(t *testing.T) (string, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skip proxy build in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	bundle := filepath.Join(t.TempDir(), "adapter")
	if _, err := Generate(Options{AgentID: "ctx-agent", Kind: "legacy-http", Output: bundle, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "generated-adapter.exe")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	build.Dir = filepath.Join(bundle, "adapter")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("generated proxy build failed: %v\n%s", err, out)
	}
	return binary, bundle
}

func startProxy(t *testing.T, binary, upstreamURL string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"AGENT_ENDPOINT_URL="+upstreamURL,
		"AGENT_SIGNING_SECRET=e2e-proxy-secret",
		"ADAPTER_LISTEN_ADDR="+addr,
	)
	var logs strings.Builder
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	ready := fmt.Sprintf("http://%s/health/ready", addr)
	for i := 0; i < 100; i++ {
		resp, err := http.Get(ready)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return addr
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("proxy never became ready: %s", logs.String())
	return ""
}

type capturedRequest struct {
	Header http.Header
	Body   string
	Method string
	Path   string
}

func TestGeneratedProxyForwardsSignedContext(t *testing.T) {
	binary, _ := buildGeneratedProxy(t)
	var mu = make(chan capturedRequest, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu <- capturedRequest{Header: r.Header.Clone(), Body: string(body), Method: r.Method, Path: r.URL.Path}
		_ = json.NewEncoder(w).Encode(map[string]any{"output": map[string]any{"answer": "pong"}})
	}))
	defer upstream.Close()
	addr := startProxy(t, binary, upstream.URL)

	envelope := map[string]any{
		"protocol_version": "agent-execution/v2",
		"context_token":    "tok-signed-123",
		"scope": map[string]any{
			"tenant_id": "tenant-1", "department_id": "dept-1", "application_id": "app-1",
			"agent_instance_id": "inst-1", "agent_id": "agent-1", "agent_version_id": "ver-1",
			"principal_type": "user", "principal_id": "user-1", "session_id": "sess-1",
			"run_id": "run-1", "authorization_epoch": 3, "trace_id": "trace-9",
		},
		"operation":       "invoke",
		"idempotency_key": "idem-1",
		"input_schema":    "schema://qa",
		"input":           map[string]any{"question": "hello"},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/internal/agent-execution/v2/invoke", addr), "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status=%d body=%s", resp.StatusCode, respBody)
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("proxy response invalid json: %v", err)
	}
	if !reflect.DeepEqual(out["output"], map[string]any{"answer": "pong"}) {
		t.Fatalf("proxy response passthrough broken: %v", out)
	}

	select {
	case captured := <-mu:
		if captured.Method != http.MethodPost || captured.Path != "/agent/invoke" {
			t.Fatalf("upstream got %s %s", captured.Method, captured.Path)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(captured.Body), &payload); err != nil {
			t.Fatalf("upstream body invalid json: %v", err)
		}
		if !reflect.DeepEqual(payload["input"], map[string]any{"question": "hello"}) {
			t.Fatalf("upstream input mismatch: %v", payload)
		}
		expect := map[string]string{
			"X-Context-Token":           "tok-signed-123",
			"X-Idempotency-Key":         "idem-1",
			"X-Scope-Tenant-ID":         "tenant-1",
			"X-Scope-Department-ID":     "dept-1",
			"X-Scope-Application-ID":    "app-1",
			"X-Scope-Agent-Instance-ID": "inst-1",
			"X-Scope-Agent-ID":          "agent-1",
			"X-Scope-Agent-Version-ID":  "ver-1",
			"X-Scope-Principal-Type":    "user",
			"X-Scope-Principal-ID":      "user-1",
			"X-Scope-Session-ID":        "sess-1",
			"X-Scope-Run-ID":            "run-1",
			"X-Trace-ID":                "trace-9",
		}
		for header, want := range expect {
			if got := captured.Header.Get(header); got != want {
				t.Fatalf("header %s=%q want %q", header, got, want)
			}
		}
		if epoch := captured.Header.Get("X-Scope-Authorization-Epoch"); epoch != "" {
			t.Fatalf("numeric scope field must not be forwarded, got %q", epoch)
		}
		mac := hmac.New(sha256.New, []byte("e2e-proxy-secret"))
		mac.Write([]byte(captured.Body))
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := captured.Header.Get("X-Context-Signature"); got != wantSig {
			t.Fatalf("X-Context-Signature=%q want %q", got, wantSig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the proxied request")
	}
}

func TestGeneratedProxyLegacyBodyHasNoContextHeaders(t *testing.T) {
	binary, _ := buildGeneratedProxy(t)
	requests := make(chan capturedRequest, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{Header: r.Header.Clone(), Body: string(body)}
		_, _ = w.Write([]byte(`{"output":{"answer":"ok"}}`))
	}))
	defer upstream.Close()
	addr := startProxy(t, binary, upstream.URL)

	resp, err := http.Post(fmt.Sprintf("http://%s/agent/invoke", addr), "application/json", strings.NewReader(`{"question":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status=%d body=%s", resp.StatusCode, body)
	}
	select {
	case captured := <-requests:
		if captured.Header.Get("X-Context-Token") != "" {
			t.Fatalf("legacy body must not produce X-Context-Token, got %q", captured.Header.Get("X-Context-Token"))
		}
		if captured.Header.Get("X-Scope-Tenant-ID") != "" {
			t.Fatalf("legacy body must not produce X-Scope headers, got %q", captured.Header.Get("X-Scope-Tenant-ID"))
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(captured.Body), &payload); err != nil {
			t.Fatalf("upstream body invalid json: %v", err)
		}
		if !reflect.DeepEqual(payload["input"], map[string]any{"question": "hi"}) {
			t.Fatalf("legacy input wrap mismatch: %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the proxied request")
	}
}
