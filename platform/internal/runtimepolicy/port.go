package runtimepolicy

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Decision struct {
	TimeoutSeconds int
	MaxRetries     int
	Allowed        bool
}

type Port interface {
	Resolve(context.Context, sharedkernel.Scope, policyasset.Snapshot) (Decision, error)
}
