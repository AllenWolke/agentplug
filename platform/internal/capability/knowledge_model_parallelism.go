package capability

import (
	"context"
	"net/http"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
)

// Knowledge batching may not assume that a published local deployment can run
// two model calls. Unknown/automatic routes are conservative; real admission
// and current capacity leases still run separately for every physical call.
func knowledgeSelectionParallelism(selected modelgateway.Selection) int {
	if selected.TrustZone == modelgovernance.TrustLocal {
		if selected.CapacityUnits >= 2 {
			return 2
		}
		return 1
	}
	if selected.TrustZone == modelgovernance.TrustExternal || selected.TrustZone == modelgovernance.TrustPrivate {
		return 2
	}
	return 1
}

func (m *Module) knowledgeModelParallelism(r *http.Request, op envelope) func(context.Context) (int, error) {
	return func(ctx context.Context) (int, error) {
		if m.modelAccess == nil || op.Policy.Model.Routing != nil {
			return 1, nil
		}
		// Resolve lazily only when a native rerank is about to use the model.
		// A knowledge grant/cache lookup alone cannot read model metadata.
		if err := m.knowledgeModelCheck(r, op, r.Context())(ctx, "generate"); err != nil {
			return 0, err
		}
		selected, err := m.modelAccess.ResolveModel(ctx, scopeFromHarness(op.Context), op.Policy.Model.ModelVersionID)
		if err != nil {
			return 0, err
		}
		return knowledgeSelectionParallelism(selected), nil
	}
}
