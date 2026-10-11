package main

import (
	"context"

	"generated-agent/platform_entry/agentplatform"

	"github.com/cloudwego/eino/compose"
)

// The Eino Graph bridge: the platform Context (the VERIFIED scope from the PEP)
// is carried into context.Context so framework nodes never re-parse tokens and
// only ever read already-verified identity.
// Eino 图桥接：把平台 Context（经 PEP 校验的作用域）放入 context.Context，
// 框架节点不再解析令牌，只读取已验证的身份。

type platformContextKey string

const (
	platformScopeKey platformContextKey = "agent-platform.scope"
	platformRunKey   platformContextKey = "agent-platform.run-id"
)

// WithPlatformScope injects the verified scope behind the business seam.
// WithPlatformScope 把已验证的作用域注入业务接缝之后的上下文。
func WithPlatformScope(ctx context.Context, request agentplatform.ExecuteRequest) context.Context {
	ctx = context.WithValue(ctx, platformScopeKey, request.Scope)
	return context.WithValue(ctx, platformRunKey, request.Scope.RunID)
}

// RunIDFromContext lets business nodes observe which verified run they serve.
// RunIDFromContext 让业务节点获知自己服务于哪个已验证运行。
func RunIDFromContext(ctx context.Context) string {
	if value, ok := ctx.Value(platformRunKey).(string); ok {
		return value
	}
	return ""
}

// TenantIDFromContext keeps tenant identity available to the graph without
// leaking it into logs or telemetry attributes.
// TenantIDFromContext 让业务图可取租户身份，但不得把它写入日志或遥测属性。
func TenantIDFromContext(ctx context.Context) string {
	if scope, ok := ctx.Value(platformScopeKey).(agentplatform.ScopeKey); ok {
		return scope.TenantID
	}
	return ""
}

// NewEchoGraph builds the example Eino business graph: START → echo → END.
// Replace the node with a real ChatClient/Tool graph; the platform boundary and
// the verified context values stay exactly the same.
// NewEchoGraph 构建示例 Eino 业务图：START → echo → END。将该节点替换为真实的
// ChatClient/Tool 图即可；平台边界与已验证上下文的传递方式保持不变。
func NewEchoGraph(ctx context.Context) (compose.Runnable[map[string]any, map[string]any], error) {
	graph := compose.NewGraph[map[string]any, map[string]any]()
	echo := compose.InvokableLambda(func(ctx context.Context, input map[string]any) (map[string]any, error) {
		return map[string]any{
			"framework": "eino",
			"run_id":    RunIDFromContext(ctx),
			"tenant_id": TenantIDFromContext(ctx),
			"input":     input,
		}, nil
	})
	if err := graph.AddLambdaNode("echo", echo); err != nil {
		return nil, err
	}
	if err := graph.AddEdge(compose.START, "echo"); err != nil {
		return nil, err
	}
	if err := graph.AddEdge("echo", compose.END); err != nil {
		return nil, err
	}
	return graph.Compile(ctx)
}
