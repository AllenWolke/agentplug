package capability

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestKnownIncompleteModelUsageSettlesOnceAndReplayStillFails(t *testing.T) {
	access := modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal, DeploymentID: "deployment-a", EndpointRef: "service://local-model", CapacityUnits: 4}, nil
	})
	budgets := &captureModelBudgetStore{}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Incomplete: true, FinishReason: "length", InputTokens: 79, OutputTokens: 256}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(access, gateway)
	module.SetModelBilling(testApprovedPriceResolver(), budgets)
	module.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "known-incomplete", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "teaching question"}}}
	for i := 0; i < 2; i++ {
		response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
		if response.Code != http.StatusBadGateway || !bytes.Contains(response.Body.Bytes(), []byte("MODEL_OUTPUT_INCOMPLETE")) {
			t.Fatalf("truncated answer advertised as success or unknown: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if gateway.calls != 1 || len(budgets.settled) != 1 || budgets.settled[0].InputTokens != 79 || budgets.settled[0].OutputTokens != 256 {
		t.Fatalf("known billable failure resent or charged twice: calls=%d events=%+v", gateway.calls, budgets.settled)
	}
}
