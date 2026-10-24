package main

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/agent-platform-sdk-go/agentplatform/telemetry"
)

//go:embed manifest.json
var publishedManifest []byte

var (
	errCapabilityInvalid = errors.New("platform capability is invalid")
	errCapabilityMissing = errors.New("platform capability is not configured")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Fail closed: without platform-injected verification material the Agent
	// refuses to start rather than accepting unverified callers.
	// 失败闭合：没有平台注入的校验材料时，Agent 拒绝启动，而不是接受未验证的调用方。
	key, err := publicKeyFromEnv()
	if err != nil {
		log.Fatal("platform capability verification is not configured: ", err)
	}
	agentID := agentIDFromEnv()
	capability, err := agentplatform.CapabilityConfigFromEnv()
	if err != nil || capability == nil || capability.WorkloadClientID == "" {
		log.Fatal("platform capability wiring is incomplete")
	}
	limiter, limitError := agentplatform.NewCapabilitySendLimiter(16)
	if limitError != nil {
		log.Fatal("invalid capability concurrency")
	}
	capability.SendLimiter = limiter
	if os.Getenv("AGENT_PLATFORM_CAPABILITY_TIMING") == "1" {
		capability.ObserveCall = func(sample agentplatform.CapabilityObservation) {
			log.Printf("capability_observation path=%q status=%q elapsed_ms=%.3f", agentplatform.SafeCapabilityPath(sample.Path), sample.Status, sample.WallMS)
		}
	}
	// Absence of a collector must never fail startup; telemetry.Setup returns
	// the no-op tracer for an empty endpoint.
	// 缺失收集器绝不能导致启动失败；端点为空时 telemetry.Setup 返回 no-op tracer。
	tracer, shutdown, err := telemetry.Setup(context.Background(), agentID, strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")))
	if err != nil {
		log.Fatal("telemetry setup failed: ", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	server, err := agentplatform.NewExecutionServer(agentplatform.ServerConfig{
		PublicKey:    key,
		Issuer:       issuerFromEnv(),
		Audience:     audienceFromEnv(),
		AgentID:      agentID,
		AgentVersion: "0.3.0",
		Manifest:     publishedManifest,
		// The lifecycle entries travel together so a started run can always be
		// observed, resumed and cancelled.
		// 生命周期入口同行，已启动的运行始终可观察、可恢复、可取消。
		Capabilities: []string{"invoke", "run", "resume", "cancel", "events"},
		// NOT FOR L2/L3: swap in a scoped durable RunStore for production.
		// 不可用于 L2/L3：生产环境请替换为带 Scope 的持久化 RunStore。
		Store:                      agentplatform.NewMemoryRunStore(),
		Tracer:                     tracer,
		Capability:                 capability,
		RecoveryCheckpointSelector: recoveryCheckpointSelector,
		Invoke:                     invokeBusiness,
		Run:                        runBusiness,
	})
	if err != nil {
		log.Fatal("execution server configuration is incomplete: ", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	address := strings.TrimSpace(os.Getenv("AGENT_HTTP_ADDR"))
	if address == "" {
		address = ":" + port
	}
	if err := server.ListenAndServe(ctx, address); err != nil {
		log.Fatal(err)
	}
}

// The audience identifies the platform execution service; the SDK separately
// binds the signed scope to this Agent ID before entering business code.
const defaultPlatformAudience = "agent-runtime"

func issuerFromEnv() string {
	if issuer := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_ISSUER")); issuer != "" {
		return issuer
	}
	return "platform"
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
	return "example-go-operations"
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
