package capability

import (
	"context"
	"errors"
	"net/http"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
)

// Trusted in-process seams. They never enter Agent JSON or grant authority
// from a claimed model_version_id. Current catalog/IAM checks still run for
// every reused receipt, including cross-Run cache hits.
type KnowledgeModelReceiptCheck func(context.Context, string, string) error

func (m *Module) knowledgeRoutingBinding(ctx context.Context, op envelope) (policyasset.ModelSelectionBinding, bool, error) {
	if op.Policy.Model.Routing == nil {
		return policyasset.ModelSelectionBinding{}, false, nil
	}
	if op.Policy.Model.ValidateRouting() != nil || op.Policy.Model.Routing.ExecutionContextSHA256 != policyasset.RoutingExecutionContextSHA256(op.Policy) {
		return policyasset.ModelSelectionBinding{}, false, &KnowledgeModelError{Status: 403, Code: "MODEL_SELECTION_MISMATCH"}
	}
	store, ok := m.modelStore.(policyasset.ModelSelectionStore)
	if !ok {
		return policyasset.ModelSelectionBinding{}, false, &KnowledgeModelError{Status: 503, Code: "MODEL_ROUTING_UNAVAILABLE"}
	}
	b, found, err := store.LookupModelSelection(ctx, scopeFromHarness(op.Context))
	if err != nil {
		return b, false, &KnowledgeModelError{Status: 503, Code: "MODEL_ROUTING_UNAVAILABLE"}
	}
	if !found {
		return b, false, nil
	}
	if !validModelSelectionBinding(scopeFromHarness(op.Context), b) || b.PolicySHA256 != op.Policy.Hash {
		return b, false, &KnowledgeModelError{Status: 409, Code: "MODEL_IDEMPOTENCY_CONFLICT"}
	}
	fallback := op.Policy.Model.Routing.Availability
	return b, b.Selection.EffectiveMode() == "automatic" || fallback != nil && fallback.Version == "model-route-availability/v2" && fallback.ManualFallback, nil
}

func knowledgeMinimumTier(op envelope, b policyasset.ModelSelectionBinding) int {
	rank := policyasset.ModelComplexityRank(b.TaskComplexity)
	if rank == 0 {
		rank = 3
	}
	if b.Selection.EffectiveMode() == "manual" {
		for _, candidate := range op.Policy.Model.Routing.Candidates {
			if candidate.ModelVersionID == op.Policy.Model.ModelVersionID {
				rank = max(rank, policyasset.ModelComplexityRank(candidate.MaxComplexity))
			}
		}
	}
	return rank
}

func (m *Module) knowledgeModelCacheBinding(op envelope, lifetime context.Context) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if err := lifetime.Err(); err != nil {
			return "", err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		b, active, err := m.knowledgeRoutingBinding(ctx, op)
		if err != nil || !active {
			return "", err
		}
		return modelRouteHash(struct{ Mode, Task, Complexity string }{b.Selection.EffectiveMode(), b.TaskSHA256, b.TaskComplexity}), nil
	}
}

func (m *Module) knowledgeModelReceiptCheck(parent *http.Request, op envelope, lifetime context.Context) KnowledgeModelReceiptCheck {
	return func(ctx context.Context, operation, version string) error {
		if version == "" {
			return &KnowledgeModelError{Status: 403, Code: "MODEL_SELECTION_MISMATCH"}
		}
		return m.knowledgeModelVersionCheck(parent, op, lifetime, version)(ctx, operation)
	}
}

// Before a fresh routed stage the primary need not be available. Check a
// currently authorized candidate without selecting/persisting/sending one;
// the existing native router still owns capabilities, quality, price, budget,
// availability and immutable physical attempt identity at actual invocation.
func (m *Module) knowledgeModelCheck(parent *http.Request, op envelope, lifetime context.Context) KnowledgeModelCheck {
	return func(ctx context.Context, operation string) error {
		if err := lifetime.Err(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if operation != "generate" {
			return m.knowledgeModelVersionCheck(parent, op, lifetime, "")(ctx, operation)
		}
		b, active, err := m.knowledgeRoutingBinding(ctx, op)
		if err != nil {
			return err
		}
		if !active {
			return m.knowledgeModelVersionCheck(parent, op, lifetime, "")(ctx, operation)
		}
		last := error(&KnowledgeModelError{Status: 403, Code: "MODEL_ACCESS_DENIED"})
		var unavailable error
		for _, candidate := range op.Policy.Model.Routing.Candidates {
			if policyasset.ModelComplexityRank(candidate.MaxComplexity) < knowledgeMinimumTier(op, b) {
				continue
			}
			err := m.knowledgeModelVersionCheck(parent, op, lifetime, candidate.ModelVersionID)(ctx, operation)
			if err == nil {
				return nil
			}
			var denied *KnowledgeModelError
			if !errors.As(err, &denied) || denied.Code == "CAPABILITY_DENIED" {
				return err
			}
			last = err
			if denied.Status >= 500 {
				unavailable = err
			}
		}
		if unavailable != nil {
			return unavailable
		}
		return last
	}
}

func (m *Module) knowledgeRoutedModel(ctx context.Context, op envelope, version string, b policyasset.ModelSelectionBinding) (modelgateway.Selection, error) {
	metadata, ok := m.modelAccess.(modelgateway.RoutingMetadataResolver)
	if !ok {
		return modelgateway.Selection{}, &KnowledgeModelError{Status: 503, Code: "MODEL_ROUTING_UNAVAILABLE"}
	}
	for _, candidate := range op.Policy.Model.Routing.Candidates {
		if candidate.ModelVersionID != version {
			continue
		}
		if policyasset.ModelComplexityRank(candidate.MaxComplexity) < knowledgeMinimumTier(op, b) {
			return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
		}
		current, err := metadata.ResolveRoutingModel(ctx, scopeFromHarness(op.Context), version)
		if err != nil {
			return modelgateway.Selection{}, err
		}
		if current.Kind != "chat" || current.CapabilitySHA256() != candidate.CapabilitySHA256 {
			return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
		}
		return current.Selection, nil
	}
	return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
}
