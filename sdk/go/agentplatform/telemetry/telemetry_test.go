package telemetry

import (
	"context"
	"testing"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

// TestSetupWithoutEndpointFailsSafe pins the fail-safe contract: absence of a
// collector yields the no-op tracer and never fails startup.
// TestSetupWithoutEndpointFailsSafe 钉住失败安全契约：缺失收集器时返回 no-op
// tracer，绝不导致启动失败。
func TestSetupWithoutEndpointFailsSafe(t *testing.T) {
	tracer, shutdown, err := Setup(context.Background(), "agent-test", "")
	if err != nil {
		t.Fatalf("empty endpoint failed startup: %v", err)
	}
	if tracer == nil {
		t.Fatal("tracer is nil")
	}
	ctx, span := tracer.StartSpan(context.Background(), "smoke")
	if ctx == nil {
		t.Fatal("context missing after StartSpan")
	}
	span.End()
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

// TestSetupWithInsecureHTTPEndpointBuildsProvider proves an http:// endpoint
// constructs the OTLP/HTTP pipeline without contacting the network.
// TestSetupWithInsecureHTTPEndpointBuildsProvider 证明 http:// 端点可在不触网的
// 前提下构建 OTLP/HTTP 管线。
func TestSetupWithInsecureHTTPEndpointBuildsProvider(t *testing.T) {
	tracer, shutdown, err := Setup(context.Background(), "agent-test", "http://127.0.0.1:4318")
	if err != nil {
		t.Fatalf("insecure endpoint failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	if tracer == nil {
		t.Fatal("tracer is nil")
	}
	var seam agentplatform.Tracer = tracer
	_, span := seam.StartSpan(context.Background(), "smoke")
	span.End()
}
