package execution

import (
	"context"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// CapabilityAuthorizationAction classifies only the persisted, lease-verified
// command. Browser headers and capability payloads cannot choose an IAM action.
// Internal indexing is management work; it never grants business run rights.
func (m *Module) CapabilityAuthorizationAction(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (string, error) {
	return m.ValidateLiveLeaseAndAction(ctx, scope, operation, bodyHash, policyHash)
}

// ValidateLiveLeaseAndAction validates and classifies the same freshly read Run.
// Facts never escape into a cache or replace later provider/disclosure fences.
func (m *Module) ValidateLiveLeaseAndAction(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (string, error) {
	run, err := m.validatedLiveLease(ctx, scope, operation, bodyHash, policyHash)
	if err != nil {
		return "", err
	}
	command, err := commandAuthorityHeaders.Decode(run.RequestJSON)
	if err != nil {
		return "", contract.ErrSchemaValidation
	}
	if run.AgentEndpoint == "" && command.InputSchema == KnowledgeIndexInputSchema && command.ContextTokenEmpty && (command.Operation == "invoke" || command.Operation == "run") {
		return "policy.manage", nil
	}
	return "run", nil
}
