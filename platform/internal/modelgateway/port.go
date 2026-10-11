package modelgateway

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type GenerateRequest struct {
	Prompt         string
	Model          string
	ModelVersionID string
	ProviderID     string
	ModelID        string
	Messages       []Message
	Temperature    float64
	MaxTokens      int
	FunctionNames  []string
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type GenerateResult struct {
	Text         string
	InputTokens  int
	OutputTokens int
	// Incomplete preserves known billable usage without claiming an answer.
	Incomplete   bool
	FinishReason string
	ToolCalls    []ToolCall
}

// UsageEmbeddingPort is required by billable embedding execution. A provider
// returning vectors without real token usage cannot use this governed path.
type EmbeddingResult struct {
	Vectors     [][]float32
	InputTokens int
}
type UsageEmbeddingPort interface {
	EmbedWithUsage(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) (EmbeddingResult, error)
}

type Port interface {
	Generate(context.Context, sharedkernel.Scope, policyasset.Snapshot, GenerateRequest) (GenerateResult, error)
	Embed(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) ([][]float32, error)
}

// Selection is resolved from the approved model catalog, never from Agent
// request fields. Provider/model IDs are carried to the invocation adapter.
type Selection struct {
	ModelVersionID string
	ProviderID     string
	ProviderKey    string
	ModelID        string
	ModelKey       string
	TrustZone      string
	DeploymentID   string
	EndpointRef    string
	CapacityUnits  int64
}

// AccessResolver performs fail-closed model-version approval and scoped policy
// checks using identity-derived execution scope.
type AccessResolver interface {
	ResolveModel(context.Context, sharedkernel.Scope, string) (Selection, error)
}
