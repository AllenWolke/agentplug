package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

// TestProcessAdapterCommandHelper is launched by the black-box test as the
// pre-registered process. It writes a marker only when the adapter actually
// reaches the external command. / 该测试函数作为预注册进程被黑盒测试
// 启动；只有 Adapter 真正执行外部命令时才写入标记文件。
func TestProcessAdapterCommandHelper(t *testing.T) {
	marker := os.Getenv("PROCESS_ADAPTER_TEST_MARKER")
	if marker == "" {
		return
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatalf("read adapter payload: %v", err)
	}
	if err := os.WriteFile(marker, []byte("executed"), 0o600); err != nil {
		t.Fatalf("write execution marker: %v", err)
	}
	_, _ = os.Stdout.Write([]byte(`{"ok":true}`))
}

func TestProcessAdapterRejectsMalformedAndMissingCapabilityWithoutExecutingCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed.marker")
	startProcessAdapter(t, marker, make(ed25519.PublicKey, ed25519.PublicKeySize))
	client := &http.Client{Timeout: 3 * time.Second}

	resp := postRaw(t, client, "http://127.0.0.1:8080/internal/agent-execution/v2/invoke", []byte("{"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		resp.Body.Close()
		t.Fatalf("malformed body status=%d, want %d", resp.StatusCode, http.StatusUnprocessableEntity)
	}
	resp.Body.Close()

	request := agentplatform.ExecuteRequest{
		ProtocolVersion: agentplatform.ProtocolVersion,
		Operation:       "invoke",
		Scope:           agentplatform.ScopeKey{RunID: "run-test"},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	resp = postRaw(t, client, "http://127.0.0.1:8080/internal/agent-execution/v2/invoke", body)
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("missing capability status=%d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	resp.Body.Close()

	request.ContextToken = "malformed-capability"
	body, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	resp = postWithAuthorization(t, client, "http://127.0.0.1:8080/internal/agent-execution/v2/invoke", body, request.ContextToken)
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Fatalf("malformed capability status=%d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	resp.Body.Close()

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("external command executed for rejected request, stat=%v", err)
	}
}

// TestProcessAdapterRefusesToStartWithoutRegisteredSandbox proves the adapter
// fails closed: a missing CPU/memory/PID/network envelope aborts start-up
// instead of degrading into an unisolated process run.
// TestProcessAdapterRefusesToStartWithoutRegisteredSandbox 证明 Adapter 失败闭合：
// 缺少 CPU/内存/PID/网络信封时中止启动，而不是退化成无隔离的进程执行。
func TestProcessAdapterRefusesToStartWithoutRegisteredSandbox(t *testing.T) {
	binary := buildProcessAdapter(t)
	command, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"PROCESS_COMMAND="+command,
		"PLATFORM_CONTEXT_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize)),
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("adapter started without a registered sandbox; output=%s", output)
	}
	if !strings.Contains(string(output), "PROCESS_SANDBOX_MEMORY_BYTES") {
		t.Fatalf("start-up failure did not name the missing sandbox bound: %s", output)
	}
}

// TestProcessAdapterHealthExposesSandboxBounds keeps the registered isolation
// envelope observable so an operator can prove what the adapter will enforce.
// TestProcessAdapterHealthExposesSandboxBounds 让已登记的隔离信封可观测，运维可据此
// 证明 Adapter 实际会施加哪些限制。
func TestProcessAdapterHealthExposesSandboxBounds(t *testing.T) {
	startProcessAdapter(t, filepath.Join(t.TempDir(), "marker"), make(ed25519.PublicKey, ed25519.PublicKeySize))
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8080/health/ready")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	var payload struct {
		Sandbox struct {
			MaxMemoryBytes int64  `json:"max_memory_bytes"`
			MaxCPUSeconds  int    `json:"max_cpu_seconds"`
			MaxProcesses   int    `json:"max_processes"`
			Network        string `json:"network"`
		} `json:"sandbox"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health payload: %v", err)
	}
	if payload.Sandbox.MaxMemoryBytes != 268435456 || payload.Sandbox.MaxCPUSeconds != 10 || payload.Sandbox.MaxProcesses != 64 || payload.Sandbox.Network != "container" {
		t.Fatalf("health did not report the registered sandbox: %+v", payload.Sandbox)
	}
}

func buildProcessAdapter(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "process-adapter")
	if filepath.Ext(mustExecutable(t)) == ".exe" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build process adapter: %v", err)
	}
	return binary
}

func startProcessAdapter(t *testing.T, marker string, public ed25519.PublicKey) *exec.Cmd {
	t.Helper()
	adapterBinary := buildProcessAdapter(t)
	command, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	args, _ := json.Marshal([]string{"-test.run=TestProcessAdapterCommandHelper"})
	childEnv, _ := json.Marshal([]string{"PROCESS_ADAPTER_TEST_MARKER=" + marker})
	cmd := exec.Command(adapterBinary)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		"PROCESS_COMMAND="+command,
		"PROCESS_ARGS_JSON="+string(args),
		"PROCESS_ADAPTER_TEST_MARKER="+marker,
		"PROCESS_ENV_JSON="+string(childEnv),
		"PROCESS_SANDBOX_MEMORY_BYTES=268435456",
		"PROCESS_SANDBOX_CPU_SECONDS=10",
		"PROCESS_SANDBOX_MAX_PROCESSES=64",
		"PROCESS_SANDBOX_MAX_OUTPUT_BYTES=1048576",
		"PROCESS_SANDBOX_TIMEOUT_SECONDS=30",
		"PROCESS_SANDBOX_NETWORK=container",
		"PLATFORM_CONTEXT_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(public),
		"PLATFORM_CONTEXT_ISSUER=platform",
		"AGENT_ID=process-test-agent",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start process adapter: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitReady(t, "http://127.0.0.1:8080/health/ready")
	return cmd
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	return executable
}

func postRaw(t *testing.T, client *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
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

func postWithAuthorization(t *testing.T, client *http.Client, url string, body []byte, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
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

func waitReady(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("adapter did not become ready: %s", url)
}
