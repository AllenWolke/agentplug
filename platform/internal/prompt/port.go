package prompt

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Port interface {
	Resolve(context.Context, sharedkernel.Scope, policyasset.Snapshot) (string, error)
	Render(context.Context, sharedkernel.Scope, policyasset.Snapshot, map[string]any) (string, error)
}
