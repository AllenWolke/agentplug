package capability

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/prompt"
)

// Keep original command messages for invocation/receipt fingerprints. Only the
// provider input is namespaced; all routing, limits and admission include it.
func (m *Module) invocationContext(op envelope, messages []modelgateway.Message, embedding bool) ([]modelgateway.Message, string, error) {
	if embedding {
		return messages, "", nil
	}
	rendered, err := prompt.InvocationMessages(op.Policy.Prompt.Template, messages)
	if err != nil {
		return nil, "", err
	}
	key := m.signingSecret
	if key == "" {
		key = m.internalToken
	}
	return modelgateway.PrepareContextCachePrefix(scopeFromHarness(op.Context), op.Policy, rendered, []byte(key))
}

// In-process packing uses the exact gateway rendering and authenticated prefix.
// This is a pure preflight: no routing, reservation, provider or receipt write.
func (m *Module) knowledgeModelInputFits(op envelope) func([]modelgateway.Message, bool) bool {
	return func(messages []modelgateway.Message, requireJSON bool) bool {
		wire, _, err := m.invocationContext(op, messages, false)
		return err == nil && ValidateModelContextLimit(op.Policy.Model, wire, op.Policy.Tool, nil, requireJSON) == nil
	}
}

func (m *Module) knowledgeModelSchemaInputFits(op envelope) func([]modelgateway.Message, bool, json.RawMessage, string) bool {
	return func(messages []modelgateway.Message, requireJSON bool, raw json.RawMessage, mode string) bool {
		wire, _, err := m.invocationContext(op, messages, false)
		return err == nil && ValidateModelContextWithResponseSchema(op.Policy.Model, wire, op.Policy.Tool, nil, requireJSON, raw, mode) == nil
	}
}

func (m *Module) checkContextCacheModel(ctx context.Context, op envelope) error {
	if op.Policy.Model.ContextCache == nil {
		return nil
	}
	metadata, ok := m.modelAccess.(modelgateway.RoutingMetadataResolver)
	if !ok {
		return modelgovernance.ErrModelAccessDenied
	}
	model, err := metadata.ResolveRoutingModel(ctx, scopeFromHarness(op.Context), op.Policy.Model.ModelVersionID)
	if err != nil {
		return err
	}
	if model.Selection.ModelVersionID != op.Policy.Model.ModelVersionID || !op.Policy.Model.AllowsContextCacheMode(model.ContextCacheMode) {
		return modelgovernance.ErrModelAccessDenied
	}
	return nil
}
