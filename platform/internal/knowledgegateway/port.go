package knowledgegateway

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Chunk struct {
	ID       string
	Content  string
	Source   string
	Metadata map[string]string
}

type SearchRequest struct {
	Query string
	TopK  int
}

type Port interface {
	Search(context.Context, sharedkernel.Scope, policyasset.Snapshot, SearchRequest) ([]Chunk, error)
	Replay(context.Context, sharedkernel.Scope, policyasset.Snapshot, string) ([]Chunk, error)
}
