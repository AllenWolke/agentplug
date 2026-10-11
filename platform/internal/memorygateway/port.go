package memorygateway

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Entry struct{ Key, Value string }

type Port interface {
	Load(context.Context, sharedkernel.Scope, policyasset.Snapshot, string) ([]Entry, error)
	Append(context.Context, sharedkernel.Scope, policyasset.Snapshot, Entry) error
	Search(context.Context, sharedkernel.Scope, policyasset.Snapshot, string) ([]Entry, error)
	Delete(context.Context, sharedkernel.Scope, policyasset.Snapshot, string) error
}
