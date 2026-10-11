package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"generated-agent/platform_entry/agentplatform"
	"generated-agent/platform_entry/agentplatform/telemetry"

	"github.com/cloudwego/eino/compose"
)

// Eino remains the business graph dependency. The transport, PEP verification
// and run lifecycle come from the vendored platform SDK; the graph only runs
// behind the verified boundary and sees the platform through context values.
// Eino 是业务编排依赖：传输、PEP 校验与运行生命周期来自 vendored 平台 SDK；
// 业务图只在已验证边界之后运行，并通过 context 值感知平台。

var (
	errCapabilityInvalid = errors.New("platform capability is invalid")
	errCapabilityMissing = errors.New("platform capability is not configured")
)

// defaultPlatformAudience must equal the agent_id advertised in the manifest so
// the Gateway signs tokens for exactly this Agent.
// defaultPlatformAudience 必须与 manifest 中宣告的 agent_id 一致，使网关只为该 Agent 签发令牌。
const defaultPlatformAudience = "generated-go-eino-agent"

func main() {
	// Fail closed: without platform-injected verification material the Agent
	// refuses to start rather than accepting unverified callers.
	// 失败闭合：没有平台注入的校验材料时，Agent 拒绝启动，而不是接受未验证的调用方。
	key, err := publicKeyFromEnv()
	if err != nil {
		log.Fatal("platform capability verification is not configured: ", err)
	}
	agentID := agentIDFromEnv()
	// Absence of a collector must never fail startup; telemetry.Setup returns
	// the no-op tracer for an empty endpoint.
	// 缺失收集器绝不能导致启动失败；端点为空时 telemetry.Setup 返回 no-op tracer。
	tracer, shutdown, err := telemetry.Setup(context.Background(), agentID, strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")))
	if err != nil {
		log.Fatal("telemetry setup failed: ", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	graph, err := NewEchoGraph(context.Background())
	if err != nil {
		log.Fatal("eino graph failed to compile: ", err)
	}
	server, err := newExecutionServer(key, agentID, tracer, graph, nil)
	if err != nil {
		log.Fatal("execution server configuration is incomplete: ", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := server.ListenAndServe(context.Background(), ":"+port); err != nil {
		log.Fatal(err)
	}
}

// newExecutionServer wires the Eino graph behind the SDK transport: the graph
// only runs after PEP verification and sees the platform through context
// values. Tests reuse this exact wiring; now is optional and pins the clock.
// newExecutionServer 把 Eino 图接入 SDK 传输层之后：图只在 PEP 校验通过后运行，
// 并通过 context 值感知平台。测试复用同一接线；now 可选，用于钉住时钟。
func newExecutionServer(key ed25519.PublicKey, agentID string, tracer agentplatform.Tracer, graph compose.Runnable[map[string]any, map[string]any], now func() time.Time) (*agentplatform.ExecutionServer, error) {
	capability, err := agentplatform.CapabilityConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return agentplatform.NewExecutionServer(agentplatform.ServerConfig{
		PublicKey: key,
		Issuer:    issuerFromEnv(),
		Audience:  audienceFromEnv(),
		AgentID:   agentID,
		Now:       now,
		// The lifecycle entries travel together so a started run can always be
		// observed, resumed and cancelled.
		// 生命周期入口同行，已启动的运行始终可观察、可恢复、可取消。
		Capabilities: []string{"invoke", "run", "resume", "cancel", "events"},
		// NOT FOR L2/L3: swap in a scoped durable RunStore for production.
		// 不可用于 L2/L3：生产环境请替换为带 Scope 的持久化 RunStore。
		Store:      agentplatform.NewMemoryRunStore(),
		Tracer:     tracer,
		Capability: capability,
		Invoke: func(ctx context.Context, request agentplatform.ExecuteRequest) (map[string]any, error) {
			return graph.Invoke(WithPlatformScope(ctx, request), request.Input)
		},
		Run: func(ctx context.Context, request agentplatform.ExecuteRequest, events agentplatform.EventSink, cancelled <-chan struct{}) (map[string]any, error) {
			if err := events.Append(agentplatform.EventProgress, map[string]any{"stage": "eino-graph"}); err != nil {
				return nil, err
			}
			select {
			case <-cancelled:
				return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "run was cancelled", Retryable: false}
			case <-ctx.Done():
				return nil, &agentplatform.AppError{Code: "CANCELLED", Message: "run was cancelled", Retryable: false}
			default:
			}
			return graph.Invoke(WithPlatformScope(ctx, request), request.Input)
		},
	})
}

func issuerFromEnv() string {
	if issuer := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_ISSUER")); issuer != "" {
		return issuer
	}
	return "platform-runtime-gateway"
}

func audienceFromEnv() string {
	if audience := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_AUDIENCE")); audience != "" {
		return audience
	}
	return defaultPlatformAudience
}

func agentIDFromEnv() string {
	if agentID := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_AGENT_ID")); agentID != "" {
		return agentID
	}
	return audienceFromEnv()
}

// publicKeyFromEnv loads the platform-injected Ed25519 public key and fails
// closed when no usable material is present.
// publicKeyFromEnv 加载平台注入的 Ed25519 公钥；无可用材料时失败闭合。
func publicKeyFromEnv() (ed25519.PublicKey, error) {
	var candidates []string
	for _, name := range []string{"AGENT_PLATFORM_PUBLIC_KEY_BASE64", "PLATFORM_CONTEXT_PUBLIC_KEY"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			candidates = append(candidates, value)
		}
	}
	for _, name := range []string{"AGENT_PLATFORM_PUBLIC_KEY_FILE", "PLATFORM_CONTEXT_PUBLIC_KEY_FILE"} {
		if path := strings.TrimSpace(os.Getenv(name)); path != "" {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if value := strings.TrimSpace(string(content)); value != "" {
				candidates = append(candidates, value)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, errCapabilityMissing
	}
	for _, value := range candidates {
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
			if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) == ed25519.PublicKeySize {
				return ed25519.PublicKey(decoded), nil
			}
		}
	}
	return nil, errCapabilityInvalid
}
