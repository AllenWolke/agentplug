package toolgateway

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type InvokeRequest struct {
	ToolName string
	Input    map[string]any
}

type Result struct{ Output map[string]any }

type Port interface {
	Invoke(context.Context, sharedkernel.Scope, policyasset.Snapshot, InvokeRequest) (Result, error)
}
