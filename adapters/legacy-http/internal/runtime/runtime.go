// Package runtime assembles the adapter's HTTP surface from resolved
// configuration, so the exact responses the process serves can be exercised in
// tests instead of only by running the binary.
// runtime 包用已解析的配置组装 Adapter 的 HTTP 面，使「进程实际返回的响应」可以在
// 测试中演练，而不必只能靠运行二进制来验证。
package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/legacy-http-adapter/internal/descriptor"
	"github.com/lexagent/legacy-http-adapter/internal/mapping"
	"github.com/lexagent/legacy-http-adapter/internal/planloader"
	"github.com/lexagent/legacy-http-adapter/internal/security"
	"github.com/lexagent/legacy-http-adapter/internal/target"
)

// DefaultMaxBody bounds every request and response the adapter handles.
// DefaultMaxBody 约束 Adapter 处理的每个请求与响应。
const DefaultMaxBody = 8 << 20

// Config is the fully resolved adapter configuration. Nothing here is read from
// the environment at request time, so a running adapter cannot be reconfigured
// by a stray variable.
// Config 是已完全解析的 Adapter 配置。请求期不再读取任何环境变量，运行中的
// Adapter 不会被游离变量重新配置。
type Config struct {
	Development bool
	Upstream    *url.URL
	Path        string
	// EventsPath is the registered upstream path the execution-event stream is
	// read from. When empty the adapter refuses the events endpoint with
	// UNSUPPORTED_CAPABILITY instead of pretending to stream. / EventsPath 是读取
	// 执行事件流的已登记上游路径。为空时 Adapter 以 UNSUPPORTED_CAPABILITY 拒绝
	// 事件端点，而不是假装能流式输出。
	EventsPath       string
	Limits           descriptor.Limits
	ExpectedHash     string
	ExpectedRef      string
	MappingRequired  bool
	Plans            *planloader.Loader
	ContextPublicKey ed25519.PublicKey
	ContextIssuer    string
	AgentID          string
	MaxBody          int64
}

// EventsUnsupportedCode is returned when a caller asks for a capability this
// runtime never declared, so the platform can distinguish "not implemented"
// from a transport failure.
// EventsUnsupportedCode 在调用方请求本运行时从未声明过的能力时返回，使平台能把
// 「未实现」与传输故障区分开。
const EventsUnsupportedCode = "UNSUPPORTED_CAPABILITY"

// NoRedirect refuses to follow an upstream 3xx. Following it would let a
// compromised legacy endpoint move the platform's verified egress to a host
// that never passed the descriptor's address policy.
// NoRedirect 拒绝跟随上游 3xx。跟随会让被攻陷的存量端点把平台已校验的出站流量引到
// 一个从未通过 Descriptor 地址策略的主机。
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// NewHandler builds the adapter handler. The upstream client never follows
// redirects and always dials addresses validated by the target policy.
// NewHandler 构建 Adapter 处理器。上游客户端永不跟随重定向，且始终拨号经 target
// 策略校验过的地址。
func NewHandler(cfg Config) http.Handler {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{DialContext: target.Dialer(nil, cfg.Development)},
		CheckRedirect: NoRedirect,
	}
	handler := http.NewServeMux()
	handler.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		status := map[string]any{"status": "ready"}
		if cfg.Plans != nil {
			status["plan_revision"] = cfg.Plans.Revision()
			status["plan_digest"] = cfg.Plans.Digest()
			status["plan_degraded"] = cfg.Plans.Degraded()
		}
		write(w, 200, status)
	})
	handler.HandleFunc("/.well-known/agent-manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		id := cfg.AgentID
		if id == "" {
			id = "legacy-agent"
		}
		// The manifest advertises exactly what this process can serve: the
		// events capability appears only when an events path is configured.
		// manifest 只宣告本进程真正能提供的能力：仅当配置了事件路径时才出现 events。
		capabilities := []string{"invoke"}
		if strings.TrimSpace(cfg.EventsPath) != "" {
			capabilities = append(capabilities, "events")
		}
		write(w, 200, map[string]any{"manifest_version": "agent-manifest/v1", "agent_id": id, "version": "1.0.0", "execution_protocols": []string{"agent-execution/v2"}, "capabilities": capabilities, "schemas": map[string]string{"input": "schema://" + id + "/input/v1", "output": "schema://" + id + "/output/v1", "event": "schema://" + id + "/event/v1", "checkpoint": "schema://" + id + "/checkpoint/v1"}, "runtime": map[string]string{"transport": "http", "isolation": "container", "health_path": "/health/ready"}})
	})
	handler.HandleFunc("/internal/agent-execution/v2/invoke", func(w http.ResponseWriter, r *http.Request) {
		cfg.serveInvoke(client, w, r)
	})
	handler.HandleFunc("/internal/agent-execution/v2/runs/", func(w http.ResponseWriter, r *http.Request) {
		cfg.serveEvents(client, w, r)
	})
	return handler
}

// runIDFromEventsPath extracts the run id from the platform event path
// "/internal/agent-execution/v2/runs/<runID>/events". Any other suffix is not an
// events request and must not be served here.
// runIDFromEventsPath 从平台事件路径
// "/internal/agent-execution/v2/runs/<runID>/events" 中取出 run id。其它后缀不是
// 事件请求，不在此处处理。
func runIDFromEventsPath(path string) (string, bool) {
	const prefix = "/internal/agent-execution/v2/runs/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, "/events") {
		return "", false
	}
	runID := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/events")
	runID = strings.Trim(runID, "/")
	if runID == "" || strings.Contains(runID, "/") {
		return "", false
	}
	return runID, true
}

func (cfg Config) serveInvoke(client *http.Client, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxBody+1))
	if err != nil || int64(len(raw)) > cfg.MaxBody {
		http.Error(w, "invalid body", 400)
		return
	}
	var input agentplatform.ExecuteRequest
	if json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != "agent-execution/v2" || input.Operation != "invoke" || input.Scope.RunID == "" {
		http.Error(w, "invalid execution contract", 422)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == r.Header.Get("Authorization") || bearer != input.ContextToken {
		http.Error(w, "capability required", 401)
		return
	}
	if _, err := agentplatform.VerifyContext(input, cfg.ContextPublicKey, cfg.ContextIssuer, "agent-runtime", time.Now().UTC()); err != nil {
		http.Error(w, "invalid capability", 401)
		return
	}
	plan, ok := cfg.resolvePlan(w, input)
	if !ok {
		return
	}
	legacyInput := input.Input
	if plan != nil {
		mapped, applyErr := mapping.Apply(plan.Request, input.Input, map[string]any{"tenant_id": input.Scope.TenantID, "run_id": input.Scope.RunID}, nil)
		if applyErr != nil {
			http.Error(w, "mapping constraint violation", 422)
			return
		}
		legacyInput = mapped
	} else {
		legacyInput = withoutMappingPlan(input.Input)
	}
	legacyBody, _ := json.Marshal(legacyInput)
	// The inbound context already carries the caller's deadline; the descriptor
	// may tighten it but never extend it. / 入站上下文已携带调用方 deadline；
	// Descriptor 只能收紧、不能延长。
	outboundCtx := r.Context()
	if cfg.Limits.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		outboundCtx, cancel = context.WithTimeout(outboundCtx, time.Duration(cfg.Limits.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	upstream, err := http.NewRequestWithContext(outboundCtx, http.MethodPost, strings.TrimRight(cfg.Upstream.String(), "/")+cfg.Path, bytes.NewReader(legacyBody))
	if err != nil {
		http.Error(w, "adapter request failed", 502)
		return
	}
	// Only the allow-listed headers cross to the legacy upstream; the trace and
	// idempotency values come from the verified execution contract. / 只有白名单头
	// 跨越到存量上游；trace 与幂等值来自已校验的执行契约。
	for name, values := range security.OutboundHeaders(r.Header, input.Scope.TraceID, input.IdempotencyKey) {
		for _, value := range values {
			upstream.Header.Add(name, value)
		}
	}
	response, err := client.Do(upstream)
	if err != nil {
		// The upstream's own error text is never echoed: a legacy Agent's
		// diagnostic can carry internal hostnames, stack traces or credentials.
		// 上游自身的错误文本绝不回显：存量 Agent 的诊断里可能含内部主机名、栈回溯
		// 或凭据。
		http.Error(w, "legacy Agent unavailable", 502)
		return
	}
	defer response.Body.Close()
	responseLimit := cfg.MaxBody
	if cfg.Limits.MaxResponseBytes > 0 && cfg.Limits.MaxResponseBytes < responseLimit {
		responseLimit = cfg.Limits.MaxResponseBytes
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || int64(len(result)) > responseLimit || response.StatusCode < 200 || response.StatusCode >= 300 || !json.Valid(result) {
		http.Error(w, "invalid legacy Agent response", 502)
		return
	}
	var output map[string]any
	_ = json.Unmarshal(result, &output)
	if plan != nil {
		mapped, applyErr := mapping.Apply(plan.Response, input.Input, nil, output)
		if applyErr != nil {
			http.Error(w, "invalid legacy Agent response", 502)
			return
		}
		output = mapped
	}
	write(w, 200, map[string]any{"protocol_version": "agent-execution/v2", "run_id": input.Scope.RunID, "status": "succeeded", "output_schema": "schema://legacy/output/v1", "output": output})
}

// serveEvents relays the execution-event stream of a legacy agent. It applies
// the same capability verification and outbound header policy as invoke, then
// streams frames through as they arrive so a live stream is never turned into a
// single delayed response.
// serveEvents 转发存量 Agent 的执行事件流：施加与 invoke 相同的凭证校验与出站头
// 策略，并逐帧透传，使实时流不会退化成一次延迟响应。
func (cfg Config) serveEvents(client *http.Client, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	runID, ok := runIDFromEventsPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	if strings.TrimSpace(cfg.EventsPath) == "" {
		// The process never declared this capability, so it answers with the
		// platform's explicit "not implemented" code instead of a fake stream.
		// 本进程从未声明该能力，因此返回平台明确的「未实现」错误码，而不是假的事件流。
		writeCode(w, http.StatusNotImplemented, EventsUnsupportedCode, "execution events are not enabled for this Adapter")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxBody+1))
	if err != nil || int64(len(raw)) > cfg.MaxBody {
		http.Error(w, "invalid body", 400)
		return
	}
	var input agentplatform.EventRequest
	if json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != "agent-execution/v2" || input.Scope.RunID != runID {
		http.Error(w, "invalid event contract", 422)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == r.Header.Get("Authorization") || bearer != input.ContextToken {
		http.Error(w, "capability required", 401)
		return
	}
	if _, err := agentplatform.VerifyEventContext(input, cfg.ContextPublicKey, cfg.ContextIssuer, "agent-runtime", time.Now().UTC()); err != nil {
		http.Error(w, "invalid capability", 401)
		return
	}
	outboundCtx := r.Context()
	if cfg.Limits.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		outboundCtx, cancel = context.WithTimeout(outboundCtx, time.Duration(cfg.Limits.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	upstream, err := http.NewRequestWithContext(outboundCtx, http.MethodGet, strings.TrimRight(cfg.Upstream.String(), "/")+cfg.EventsPath, nil)
	if err != nil {
		http.Error(w, "adapter request failed", 502)
		return
	}
	for name, values := range security.OutboundHeaders(r.Header, input.Scope.TraceID, "") {
		for _, value := range values {
			upstream.Header.Add(name, value)
		}
	}
	// An event subscription is a read, not a command: the JSON content type and
	// the idempotency key do not belong on it, while the standard SSE resume
	// handshake does. / 事件订阅是读取而非命令：不该带 JSON 内容类型与幂等键，但应带
	// 标准 SSE 恢复握手。
	upstream.Header.Del("Content-Type")
	upstream.Header.Set("Accept", "text/event-stream")
	if input.AfterSeq > 0 {
		upstream.Header.Set("Last-Event-ID", strconv.FormatUint(input.AfterSeq, 10))
	}
	response, err := client.Do(upstream)
	if err != nil {
		http.Error(w, "legacy Agent unavailable", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		http.Error(w, "invalid legacy Agent event stream", 502)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	buffer := make([]byte, 8<<10)
	total := int64(0)
	for {
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > cfg.MaxBody {
				return
			}
			if _, writeErr := w.Write(buffer[:read]); writeErr != nil {
				return
			}
			_ = controller.Flush()
		}
		if readErr != nil {
			return
		}
	}
}

// resolvePlan picks the plan for this request. ok is false only when it has
// already written the error response, in which case the caller must stop. A
// nil plan with ok true means "forward without mapping". A wire plan is trusted
// only when the descriptor pins its content hash or mapping reference;
// otherwise the adapter falls back to the registered last-known-good document,
// which is what lets a plain HTTP agent be onboarded by mapping alone, with no
// code. / resolvePlan 为本请求选定计划。仅当它已写出错误响应时 ok 为 false，
// 调用方必须停止。plan 为 nil 且 ok 为 true 表示「不映射直接转发」。仅当
// Descriptor 固定了内容哈希或映射引用时才信任调用方传入的计划；否则回退到已登记的
// LKG 文档——这正是「纯 HTTP Agent 仅凭映射、无需改代码即可接入」的能力来源。
func (cfg Config) resolvePlan(w http.ResponseWriter, input agentplatform.ExecuteRequest) (*mapping.Plan, bool) {
	wirePlan, hasWirePlan := input.Input["mapping_plan"]
	if hasWirePlan {
		decoded, planErr := mapping.DecodeWirePlan(wirePlan, cfg.ExpectedHash)
		// The adapter must not become a second control plane if it is called
		// directly with an unrelated wire object. / 直接调用 Adapter 时，不能让
		// 无关的调用方对象冒充控制面。
		if planErr != nil || (cfg.ExpectedRef != "" && decoded.MappingID != cfg.ExpectedRef) || (cfg.ExpectedHash == "" && cfg.ExpectedRef == "") {
			http.Error(w, "invalid immutable mapping plan", 422)
			return nil, false
		}
		return decoded, true
	}
	if cfg.Plans != nil {
		if current, ok := cfg.Plans.Current(); ok {
			loaded := current
			return &loaded, true
		}
	}
	if cfg.MappingRequired {
		http.Error(w, "invalid immutable mapping plan", 422)
		return nil, false
	}
	return nil, true
}

func withoutMappingPlan(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		if key != "mapping_plan" {
			output[key] = value
		}
	}
	return output
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// writeCode emits a platform-shaped error envelope so the caller can branch on a
// stable machine-readable code rather than parsing prose.
// writeCode 输出平台形态的错误信封，使调用方能依据稳定的机器可读错误码分支，而
// 不是去解析自然语言。
func writeCode(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "retryable": false}})
}
