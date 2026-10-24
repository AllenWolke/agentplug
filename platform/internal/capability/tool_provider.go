package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// ToolProvider 是由平台运维装配的工具端口；业务 Agent 只调用已发布策略允许的工具。
// 身份、资源授权、幂等、租约、撤权和回执治理仍由能力网关负责。
type ToolProvider interface {
	Supports(string) bool
	Invoke(context.Context, ToolCommand) (map[string]any, error)
}

type ToolCommand struct {
	Scope   sharedkernel.Scope
	Name    string
	CallID  string
	Payload map[string]any
}

// ToolNoEffectError is a public provider classification for a proven failure
// before any side effect, including deterministic command prevalidation.
// Never use it for an uncertain write, commit, or lost provider response.
// 仅用于可证明没有副作用的失败，包括写入前的确定性校验；提交或响应不明禁止使用。
type ToolNoEffectError struct{ Err error }

func (e ToolNoEffectError) Error() string { return "read-only tool failed" }
func (e ToolNoEffectError) Unwrap() error { return errors.Join(ErrToolNotSubmitted, e.Err) }

// SetToolProvider 必须在服务启动前装配，禁止业务请求注册或替换工具实现。
func (m *Module) SetToolProvider(provider ToolProvider) { m.tools = provider }

func (m *Module) HasRegisteredTool(name string) bool {
	if isNotificationTool(name) {
		return m.notifications != nil
	}
	_, registered := m.RuntimeToolDescriptor(name)
	return registered
}

type builtinToolProvider struct{}

func (p builtinToolProvider) RegisteredTools() []string {
	return []string{"runtime.inspect", "json.validate", "clock.now"}
}
func (p builtinToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 3}, p.Supports(name)
}

func (builtinToolProvider) Supports(name string) bool {
	return name == "runtime.inspect" || name == "json.validate" || name == "clock.now"
}

func (p builtinToolProvider) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	if !p.Supports(command.Name) || command.Scope.Validate() != nil {
		return nil, ToolNoEffectError{Err: errors.New("invalid scoped tool request")}
	}
	switch command.Name {
	case "runtime.inspect":
		// 只返回调用上下文的状态，不暴露其他用户、进程环境变量或宿主文件。
		return map[string]any{"status": "ready", "checked_at": time.Now().UTC().Format(time.RFC3339Nano),
			"run_id": command.Scope.RunID, "agent_id": command.Scope.AgentID,
			"tenant_id": command.Scope.TenantID, "application_id": command.Scope.ApplicationID,
			"checks": []string{"trusted_context", "published_tool_policy", "current_authorization", "execution_lease"}}, nil
	case "clock.now":
		return map[string]any{"utc": time.Now().UTC().Format(time.RFC3339Nano)}, nil
	case "json.validate":
		valid, problems, err := validateJSONTool(command.Payload)
		if err != nil {
			return nil, ToolNoEffectError{Err: err}
		}
		return map[string]any{"valid": valid, "problems": problems}, nil
	}
	return nil, ToolNoEffectError{Err: errors.New("tool unavailable")}
}

// validateJSONTool 提供明确、有限的对象校验，不冒充完整 JSON Schema 规范实现。
func validateJSONTool(payload map[string]any) (bool, []string, error) {
	value, ok := payload["value"].(map[string]any)
	if !ok {
		return false, nil, errors.New("value must be a JSON object")
	}
	schema, ok := payload["schema"].(map[string]any)
	if !ok {
		return false, nil, errors.New("schema must be an object")
	}
	for key := range schema {
		if key != "required" && key != "properties" && key != "additional_properties" {
			return false, nil, errors.New("unsupported validation option")
		}
	}
	problems := []string{}
	if required, exists := schema["required"]; exists {
		items, ok := required.([]any)
		if !ok || len(items) > 128 {
			return false, nil, errors.New("required must be a bounded string array")
		}
		for _, item := range items {
			name, ok := item.(string)
			if !ok || strings.TrimSpace(name) == "" {
				return false, nil, errors.New("required field name is invalid")
			}
			if _, exists := value[name]; !exists {
				problems = append(problems, "missing:"+name)
			}
		}
	}
	properties := map[string]any{}
	if supplied, exists := schema["properties"]; exists {
		var ok bool
		properties, ok = supplied.(map[string]any)
		if !ok || len(properties) > 128 {
			return false, nil, errors.New("properties must be a bounded object")
		}
	}
	for name, rule := range properties {
		kind, ok := rule.(string)
		if !ok || kind != "string" && kind != "number" && kind != "boolean" && kind != "object" && kind != "array" {
			return false, nil, errors.New("unsupported property type")
		}
		actual, exists := value[name]
		if !exists {
			continue
		}
		match := false
		switch kind {
		case "string":
			_, match = actual.(string)
		case "number":
			switch actual.(type) {
			case float64, json.Number:
				match = true
			}
		case "boolean":
			_, match = actual.(bool)
		case "object":
			_, match = actual.(map[string]any)
		case "array":
			_, match = actual.([]any)
		}
		if !match {
			problems = append(problems, fmt.Sprintf("type:%s:%s", name, kind))
		}
	}
	if additional, exists := schema["additional_properties"]; exists {
		allowed, ok := additional.(bool)
		if !ok {
			return false, nil, errors.New("additional_properties must be boolean")
		}
		if !allowed {
			for name := range value {
				if _, exists := properties[name]; !exists {
					problems = append(problems, "unexpected:"+name)
				}
			}
		}
	}
	return len(problems) == 0, problems, nil
}
