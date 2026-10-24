package identity

import (
	"context"
	"slices"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const WorkloadBindingSchemaV2 = "workload-binding/v2"

// WorkloadBindingVersionValidator checks publication and ownership in Catalog.
// A version list never grants a business capability or chooses a run policy.
type WorkloadBindingVersionValidator interface {
	ValidateWorkloadBindingVersions(context.Context, sharedkernel.Scope, []string) error
}

func validateWorkloadBindingVersions(b WorkloadBinding) error {
	if b.SchemaVersion == "" {
		if len(b.AllowedAgentVersionIDs) != 0 {
			return ErrInvalidResource
		}
		return nil
	}
	if b.SchemaVersion != WorkloadBindingSchemaV2 || len(b.AllowedAgentVersionIDs) == 0 || len(b.AllowedAgentVersionIDs) > 32 {
		return ErrInvalidResource
	}
	seen := make(map[string]bool, len(b.AllowedAgentVersionIDs))
	for _, id := range b.AllowedAgentVersionIDs {
		if !validPermissionResourceID(id) || seen[id] {
			return ErrInvalidResource
		}
		seen[id] = true
	}
	if !seen[b.AgentVersionID] {
		return ErrInvalidResource
	}
	return nil
}

func workloadBindingAllowsVersion(b WorkloadBinding, version string) bool {
	if b.SchemaVersion == WorkloadBindingSchemaV2 {
		return slices.Contains(b.AllowedAgentVersionIDs, version)
	}
	return b.AgentVersionID == version
}
