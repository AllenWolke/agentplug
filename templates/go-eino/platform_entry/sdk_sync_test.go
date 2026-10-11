package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendoredSDKStaysInSyncWithTheSourceOfTruth pins the single-source-of-truth
// rule: the vendored platform SDK copy must stay byte-identical to
// sdk/go/agentplatform. Only the telemetry import rewrite is allowed, because
// the template is an independent module.
// TestVendoredSDKStaysInSyncWithTheSourceOfTruth 钉住单一事实源规则：vendored 平台
// SDK 副本必须与 sdk/go/agentplatform 逐字节一致；唯一允许的变换是 telemetry 的
// import 改写，因为模板是独立 module。
func TestVendoredSDKStaysInSyncWithTheSourceOfTruth(t *testing.T) {
	sdkRoot := filepath.Join("..", "..", "..", "sdk", "go", "agentplatform")
	if _, err := os.Stat(sdkRoot); err != nil {
		t.Skip("platform SDK sibling not present (standalone generated project)")
	}
	for _, name := range []string{"lifecycle.go", "models.go", "security.go", "server.go", "tracing.go", "capability_client.go"} {
		source, err := os.ReadFile(filepath.Join(sdkRoot, name))
		if err != nil {
			t.Fatalf("platform SDK file %s is missing: %v", name, err)
		}
		vendored, err := os.ReadFile(filepath.Join("agentplatform", name))
		if err != nil {
			t.Fatalf("vendored SDK file %s is missing: %v", name, err)
		}
		if string(source) != string(vendored) {
			t.Errorf("vendored %s drifted from the platform SDK; re-vendor it", name)
		}
	}
	source, err := os.ReadFile(filepath.Join(sdkRoot, "telemetry", "telemetry.go"))
	if err != nil {
		t.Fatalf("platform SDK telemetry is missing: %v", err)
	}
	vendored, err := os.ReadFile(filepath.Join("agentplatform", "telemetry", "telemetry.go"))
	if err != nil {
		t.Fatalf("vendored SDK telemetry is missing: %v", err)
	}
	rewritten := strings.ReplaceAll(string(source), "github.com/lexagent/agent-platform-sdk-go/agentplatform", "generated-agent/platform_entry/agentplatform")
	if rewritten != string(vendored) {
		t.Error("vendored telemetry.go drifted from the platform SDK; only the import rewrite is allowed")
	}
}
