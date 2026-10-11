package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/sidecar-adapter/internal/proxy"
)

const maxBody = 8 << 20

// unsupportedCapabilityCode is the platform's stable code for "this Adapter
// never declared that capability", so a caller can distinguish "not
// implemented" from a transport failure. / unsupportedCapabilityCode 是平台对
// 「本 Adapter 从未声明该能力」的稳定错误码，使调用方能把「未实现」与传输故障区分开。
const unsupportedCapabilityCode = "UNSUPPORTED_CAPABILITY"

func main() {
	base := strings.TrimSpace(os.Getenv("SIDECAR_UPSTREAM_URL"))
	if !strings.HasPrefix(base, "https://") {
		log.Fatal("SIDECAR_UPSTREAM_URL must be a pre-registered https URL")
	}
	// Mutual TLS is mandatory: a sidecar without its own workload identity would
	// be an unauthenticated proxy into a registered upstream. / 双向 TLS 是强制的：
	// 没有自身工作负载身份的 Sidecar 会沦为访问已登记上游的未认证代理。
	client, err := proxy.NewMutualTLSClient(proxy.TLSFiles{
		ClientCertFile: os.Getenv("SIDECAR_MTLS_CERT_FILE"),
		ClientKeyFile:  os.Getenv("SIDECAR_MTLS_KEY_FILE"),
		ServerCAFile:   os.Getenv("SIDECAR_MTLS_CA_FILE"),
	}, 30*time.Second)
	if err != nil {
		log.Fatalf("sidecar mutual TLS is required: %v", err)
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PLATFORM_CONTEXT_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Fatal("PLATFORM_CONTEXT_PUBLIC_KEY is required")
	}
	eventsPath := strings.TrimSpace(os.Getenv("SIDECAR_EVENTS_PATH"))
	if eventsPath != "" && (!strings.HasPrefix(eventsPath, "/") || strings.Contains(eventsPath, "..")) {
		log.Fatal("SIDECAR_EVENTS_PATH must be a registered absolute path")
	}
	forward := proxy.Proxy{BaseURL: base, Client: client}
	// The sidecar proxy is intentionally narrow: it validates the signed
	// capability then forwards only that capability, never raw caller identity.
	// Sidecar 代理刻意保持窄边界：先验证签名能力，再只转发该能力，绝不转发原始调用方身份。
	h := http.NewServeMux()
	h.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{"status": "ready", "mutual_tls": true, "events": eventsPath != ""})
	})
	h.HandleFunc("/.well-known/agent-manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		id := os.Getenv("AGENT_ID")
		if id == "" {
			id = "sidecar-agent"
		}
		// Advertise exactly what this process serves: events only when an events
		// path is registered; cancel/resume/checkpoint are never advertised
		// because they are refused with UNSUPPORTED_CAPABILITY. / 只宣告本进程真正
		// 提供的能力：仅登记了事件路径时才宣告 events；cancel/resume/checkpoint 因
		// 以 UNSUPPORTED_CAPABILITY 拒绝，永不宣告。
		capabilities := []string{"invoke", "health"}
		if eventsPath != "" {
			capabilities = append(capabilities, "events")
		}
		write(w, http.StatusOK, map[string]any{"manifest_version": "agent-manifest/v1", "agent_id": id, "version": "1.0.0", "execution_protocols": []string{"agent-execution/v2"}, "capabilities": capabilities, "schemas": map[string]string{"input": "schema://" + id + "/input/v1", "output": "schema://" + id + "/output/v1", "event": "schema://" + id + "/event/v1", "checkpoint": "schema://" + id + "/checkpoint/v1"}, "runtime": map[string]string{"transport": "sidecar", "isolation": "sidecar", "health_path": "/health/ready"}})
	})
	h.HandleFunc("/internal/agent-execution/v2/invoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		var input agentplatform.ExecuteRequest
		if readErr != nil || len(raw) > maxBody || json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != agentplatform.ProtocolVersion || input.Operation != "invoke" || input.Scope.RunID == "" {
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
		output, invokeErr := forward.Invoke(r.Context(), input)
		if invokeErr != nil {
			write(w, http.StatusBadGateway, agentplatform.AppError{Code: "SIDECAR_UPSTREAM_FAILED", Message: "isolated sidecar upstream failed", Retryable: true})
			return
		}
		write(w, http.StatusOK, output)
	})
	h.HandleFunc("/internal/agent-execution/v2/runs/", func(w http.ResponseWriter, r *http.Request) {
		serveRunSubresource(forward, key, eventsPath, w, r)
	})
	// Capabilities the platform contract defines but this Adapter does not
	// implement are refused with the stable platform code instead of a bare 404,
	// so a caller learns "unsupported", not "missing route". / 平台契约已定义、但本
	// Adapter 未实现的能力以稳定平台错误码拒绝，而非裸 404，使调用方得知「不支持」
	// 而不是「路由不存在」。
	for _, capability := range []string{"cancel", "resume", "checkpoint"} {
		capability := capability
		h.HandleFunc("/internal/agent-execution/v2/"+capability, func(w http.ResponseWriter, _ *http.Request) {
			writeUnsupported(w, capability)
		})
	}
	log.Fatal(http.ListenAndServe(":8080", h))
}

// serveRunSubresource serves the run-scoped sub-resources. Only the events
// subscription is implemented; every other suffix is an explicitly unsupported
// capability. / serveRunSubresource 处理运行级子资源：仅实现事件订阅，其余后缀一律
// 作为显式不支持的能力拒绝。
func serveRunSubresource(forward proxy.Proxy, key ed25519.PublicKey, eventsPath string, w http.ResponseWriter, r *http.Request) {
	const prefix = "/internal/agent-execution/v2/runs/"
	suffix := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	runID, capability := parts[0], parts[1]
	if capability != "events" {
		writeUnsupported(w, capability)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if eventsPath == "" {
		writeUnsupported(w, "events")
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if readErr != nil || len(raw) > maxBody {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	var input agentplatform.EventRequest
	if json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != agentplatform.ProtocolVersion || input.Scope.RunID != runID {
		http.Error(w, "invalid event contract", http.StatusUnprocessableEntity)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == r.Header.Get("Authorization") || bearer != input.ContextToken {
		http.Error(w, "capability required", http.StatusUnauthorized)
		return
	}
	if _, verifyErr := agentplatform.VerifyEventContext(input, key, os.Getenv("PLATFORM_CONTEXT_ISSUER"), "agent-runtime", time.Now().UTC()); verifyErr != nil {
		http.Error(w, "invalid capability", http.StatusUnauthorized)
		return
	}
	if streamErr := forward.StreamEvents(r.Context(), input, eventsPath, w, maxBody); streamErr != nil {
		write(w, http.StatusBadGateway, agentplatform.AppError{Code: "SIDECAR_EVENT_STREAM_FAILED", Message: "isolated sidecar event stream failed", Retryable: true})
	}
}

// writeUnsupported emits the platform-shaped "not implemented" envelope.
// writeUnsupported 输出平台形态的「未实现」错误信封。
func writeUnsupported(w http.ResponseWriter, capability string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code":      unsupportedCapabilityCode,
		"message":   "capability " + strconv.Quote(capability) + " is not implemented by this Adapter",
		"retryable": false,
	}})
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
