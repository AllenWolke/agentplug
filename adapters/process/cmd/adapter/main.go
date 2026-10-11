package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/process-adapter/internal/runner"
)

const maxBody = 8 << 20

func main() {
	// Re-entering as the sandbox trampoline must happen before any other
	// start-up work: the trampoline applies the registered limits and execs the
	// registered target instead of starting the HTTP server.
	// 以沙箱跳板身份重启时必须先于任何其他启动工作：跳板施加已登记限制并 exec 预注册
	// 目标命令，而不是启动 HTTP 服务。
	runner.Main()

	command := strings.TrimSpace(os.Getenv("PROCESS_COMMAND"))
	if command == "" || !filepath.IsAbs(command) || strings.Contains(command, "..") {
		log.Fatal("PROCESS_COMMAND must be an absolute pre-registered executable")
	}
	var args []string
	if raw := strings.TrimSpace(os.Getenv("PROCESS_ARGS_JSON")); raw != "" && json.Unmarshal([]byte(raw), &args) != nil {
		log.Fatal("PROCESS_ARGS_JSON must be a JSON string array")
	}
	var childEnv []string
	if raw := strings.TrimSpace(os.Getenv("PROCESS_ENV_JSON")); raw != "" && json.Unmarshal([]byte(raw), &childEnv) != nil {
		log.Fatal("PROCESS_ENV_JSON must be a JSON string array")
	}
	sandbox, err := loadSandbox()
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(os.Getenv("PROCESS_SANDBOX_REQUIRE_CGROUP_MEMORY")) == "true" {
		if err := runner.VerifyContainerMemoryLimit(sandbox.MaxMemoryBytes); err != nil {
			log.Fatalf("process sandbox memory is not enforced by the container: %v", err)
		}
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PLATFORM_CONTEXT_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Fatal("PLATFORM_CONTEXT_PUBLIC_KEY is required")
	}
	run := runner.Runner{Binary: command, Args: args, Dir: os.Getenv("PROCESS_WORKDIR"), Env: childEnv, Sandbox: sandbox}
	h := http.NewServeMux()
	h.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{
			"status": "ready",
			"sandbox": map[string]any{
				"max_memory_bytes": sandbox.MaxMemoryBytes,
				"max_cpu_seconds":  sandbox.MaxCPUSeconds,
				"max_processes":    sandbox.MaxProcesses,
				"max_output_bytes": sandbox.MaxOutputBytes,
				"timeout_seconds":  int(sandbox.Timeout / time.Second),
				"network":          sandbox.Network,
			},
		})
	})
	h.HandleFunc("/.well-known/agent-manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		id := os.Getenv("AGENT_ID")
		if id == "" {
			id = "process-agent"
		}
		write(w, http.StatusOK, map[string]any{"manifest_version": "agent-manifest/v1", "agent_id": id, "version": "1.0.0", "execution_protocols": []string{"agent-execution/v2"}, "capabilities": []string{"invoke", "health"}, "schemas": map[string]string{"input": "schema://" + id + "/input/v1", "output": "schema://" + id + "/output/v1", "event": "schema://" + id + "/event/v1", "checkpoint": "schema://" + id + "/checkpoint/v1"}, "runtime": map[string]string{"transport": "process", "isolation": "sandbox", "health_path": "/health/ready"}})
	})
	execute := func(w http.ResponseWriter, r *http.Request, operation string) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if readErr != nil || len(raw) > maxBody {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		var input agentplatform.ExecuteRequest
		if json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != agentplatform.ProtocolVersion || input.Operation != operation || input.Scope.RunID == "" {
			http.Error(w, "invalid execution contract", http.StatusUnprocessableEntity)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == r.Header.Get("Authorization") || bearer != input.ContextToken {
			http.Error(w, "capability required", http.StatusUnauthorized)
			return
		}
		if _, verifyErr := agentplatform.VerifyContext(input, ed25519.PublicKey(key), os.Getenv("PLATFORM_CONTEXT_ISSUER"), "agent-runtime", time.Now().UTC()); verifyErr != nil {
			http.Error(w, "invalid capability", http.StatusUnauthorized)
			return
		}
		output, invokeErr := run.Invoke(r.Context(), input)
		if invokeErr != nil {
			code := http.StatusBadGateway
			if errors.Is(invokeErr, runner.ErrInvalidDescriptor) {
				code = http.StatusServiceUnavailable
			}
			write(w, code, agentplatform.AppError{Code: "PROCESS_EXECUTION_FAILED", Message: "registered process execution failed", Retryable: code >= 500})
			return
		}
		write(w, http.StatusOK, output)
	}
	h.HandleFunc("/internal/agent-execution/v2/invoke", func(w http.ResponseWriter, r *http.Request) { execute(w, r, "invoke") })
	h.HandleFunc("/internal/agent-execution/v2/runs", func(w http.ResponseWriter, r *http.Request) { execute(w, r, "run") })
	log.Fatal(http.ListenAndServe(":8080", h))
}

// loadSandbox reads the operator-registered isolation envelope. Every bound is
// mandatory: an incomplete envelope aborts start-up instead of degrading to an
// unisolated run. / loadSandbox 读取运维登记的隔离信封。所有边界都是必填项：信封
// 不完整即中止启动，而不是退化成无隔离执行。
func loadSandbox() (runner.Sandbox, error) {
	memory, err := requiredInt64("PROCESS_SANDBOX_MEMORY_BYTES")
	if err != nil {
		return runner.Sandbox{}, err
	}
	cpu, err := requiredInt("PROCESS_SANDBOX_CPU_SECONDS")
	if err != nil {
		return runner.Sandbox{}, err
	}
	processes, err := requiredInt("PROCESS_SANDBOX_MAX_PROCESSES")
	if err != nil {
		return runner.Sandbox{}, err
	}
	output, err := requiredInt64("PROCESS_SANDBOX_MAX_OUTPUT_BYTES")
	if err != nil {
		return runner.Sandbox{}, err
	}
	timeout, err := requiredInt("PROCESS_SANDBOX_TIMEOUT_SECONDS")
	if err != nil {
		return runner.Sandbox{}, err
	}
	network := strings.TrimSpace(os.Getenv("PROCESS_SANDBOX_NETWORK"))
	sandbox := runner.Sandbox{
		MaxMemoryBytes: memory,
		MaxCPUSeconds:  cpu,
		MaxProcesses:   processes,
		MaxOutputBytes: output,
		Timeout:        time.Duration(timeout) * time.Second,
		Network:        network,
	}
	if err := sandbox.Validate(); err != nil {
		return runner.Sandbox{}, err
	}
	return sandbox, nil
}

func requiredInt(name string) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	value, err := strconv.Atoi(raw)
	if raw == "" || err != nil || value <= 0 {
		return 0, errors.New(name + " must be a positive integer")
	}
	return value, nil
}

func requiredInt64(name string) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	value, err := strconv.ParseInt(raw, 10, 64)
	if raw == "" || err != nil || value <= 0 {
		return 0, errors.New(name + " must be a positive integer")
	}
	return value, nil
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
