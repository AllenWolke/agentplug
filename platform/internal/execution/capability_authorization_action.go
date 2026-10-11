package execution

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// CapabilityAuthorizationAction classifies only the persisted, lease-verified
// command. Browser headers and capability payloads cannot choose an IAM action.
// Internal indexing is management work; it never grants business run rights.
func (m *Module) CapabilityAuthorizationAction(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (string, error) {
	if err := m.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
		return "", err
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil {
		return "", err
	}
	var command contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &command) != nil {
		return "", contract.ErrSchemaValidation
	}
	if run.AgentEndpoint == "" && command.InputSchema == KnowledgeIndexInputSchema && command.ContextToken == "" && (command.Operation == "invoke" || command.Operation == "run") {
		return "policy.manage", nil
	}
	return "run", nil
}
