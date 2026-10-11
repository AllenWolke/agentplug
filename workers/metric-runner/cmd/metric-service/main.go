// Command metric-service is the long-running dispatch face of the metric
// sandbox. It exposes exactly the same JSON request/response contract as the
// one-shot runner over HTTP, so the Evaluation Worker can dispatch a
// third-party plugin to an isolated process whose seccomp policy denies network
// syscalls before plugin code starts. Running the plugin here -- rather than as
// a child of the worker pod -- is what makes the "plugin has no platform
// network access" claim true instead of merely asserted.
// Command metric-service 是指标沙箱的常驻派发面。它通过 HTTP 暴露与一次性 Runner 完全相同的
// JSON 请求/响应契约，使评估 Worker 可把第三方插件派发到一个在执行前由 seccomp 禁止网络系统
// 调用的隔离进程。让插件在此运行（而不是作为 Worker Pod 的子进程）才能把「插件无平台网络访问」
// 变成事实而非声称。
package main

import (
	"crypto/subtle"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lexagent/metric-runner/internal/engine"
	"github.com/lexagent/metric-runner/internal/limits"
)

const (
	addrEnv        = "LEXAGENT_METRIC_SERVICE_ADDR"
	tokenEnv       = "LEXAGENT_METRIC_SERVICE_TOKEN"
	defaultAddr    = ":8085"
	executePath    = "/v1/metrics:execute"
	healthPath     = "/healthz"
	readinessPath  = "/readyz"
	maxHeaderBytes = 16 << 10
	// healthcheckArg lets the image serve as its own orchestrator probe: the
	// distroless base ships no shell, wget or curl, so a probe must be the
	// binary probing itself.
	// healthcheckArg 让镜像充当自身的编排探针：distroless 基础镜像没有 shell、wget 或 curl，
	// 因此探针必须是二进制对自身的探测。
	healthcheckArg = "--healthcheck"
)

func main() {
	// The sandbox trampoline re-executes this very binary, so the trampoline
	// entrypoint must be honoured before any other mode is considered.
	// 沙箱跳板会重新执行本二进制本身，因此在考虑任何其他模式之前必须先处理跳板入口。
	limits.Main()

	if isHealthcheck(os.Args[1:]) {
		os.Exit(runHealthcheck())
	}

	addr := envString(addrEnv, defaultAddr)
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if !validServiceToken(token) {
		log.Fatalf("%s must contain at least 32 bytes and cannot be a placeholder or repeated character", tokenEnv)
	}
	mux := http.NewServeMux()
	mux.Handle(executePath, requireBearer(token, http.HandlerFunc(handleExecute)))
	mux.HandleFunc(healthPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc(readinessPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	log.Printf("metric service listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("metric service stopped: %v", err)
	}
}

// requireBearer makes the dispatch endpoint private to trusted platform
// callers. Plugin code receives neither this credential nor the service env.
// requireBearer 将派发接口限制为可信平台调用方；插件代码既拿不到该凭证，也拿不到服务环境。
func requireBearer(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		provided := []byte(got)
		if len(provided) != len(want) || subtle.ConstantTimeCompare(provided, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleExecute decodes one request document and writes the engine's response.
// A body larger than the one-shot limit is refused with 413 instead of being
// truncated, so an oversized request can never be silently reinterpreted.
// handleExecute 解码单个请求文档并写出引擎响应。超过一次性上限的请求体以 413 拒绝而非被截断，
// 使超长请求绝不会被静默重新解释。
func handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(engine.MaxRequestBytes)+1))
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}
	if len(raw) > engine.MaxRequestBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(engine.Handle(r.Context(), raw))
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func isHealthcheck(args []string) bool {
	for _, arg := range args {
		if arg == healthcheckArg {
			return true
		}
	}
	return false
}

// runHealthcheck probes the local readiness endpoint and returns a process exit
// code so the orchestrator can gate on it.
// runHealthcheck 探测本地就绪端点并返回退出码，供编排系统据此裁决。
func runHealthcheck() int {
	host := envString(addrEnv, defaultAddr)
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + host + readinessPath)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// validServiceToken 拒绝弱服务凭证；不记录收到的凭证值。
func validServiceToken(token string) bool {
	token = strings.TrimSpace(token)
	runes := []rune(token)
	if len(token) < 32 || strings.Count(token, string(runes[0])) == len(runes) {
		return false
	}
	for _, marker := range []string{"replace-", "change-me", "changeme", "placeholder", "dev-internal", "dev-signing"} {
		if strings.Contains(strings.ToLower(token), marker) {
			return false
		}
	}
	return true
}
