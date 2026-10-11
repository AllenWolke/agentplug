package capability

import (
	"context"
	"crypto/ed25519"
)

// 通用治理测试的私有假工具，不会进入平台二进制或示例运行配置。
type fixtureToolProvider struct{}

func (fixtureToolProvider) Supports(name string) bool {
	return name == "fixture.read" || name == "fixture.write" || name == "fixture.update"
}

func (fixtureToolProvider) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	switch command.Name {
	case "fixture.read":
		return map[string]any{"status": "ready", "tenant_id": command.Scope.TenantID, "application_id": command.Scope.ApplicationID}, nil
	case "fixture.write":
		return map[string]any{"issue_id": "issue-" + command.CallID, "operation": "created"}, nil
	default:
		return map[string]any{"status": "updated"}, nil
	}
}

func newTestModule(token, signingSecret string, key ed25519.PublicKey, issuer, audience string) *Module {
	m := NewModule(token, signingSecret, key, issuer, audience)
	m.SetToolProvider(fixtureToolProvider{})
	return m
}

func (p fixtureToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 3}, p.Supports(name)
}
