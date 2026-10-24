package identity

import (
	"context"
	"slices"
	"testing"
)

import "github.com/lexagent/platform/internal/sharedkernel"

func TestAgentUseRequirementsRejectSensitiveUnboundedAndForeignDependencies(t *testing.T) {
	r := &completeAgentRequirementsFixture{version: "version"}
	valid, err := r.ResolveAgentUseRequirements(context.Background(), sharedkernel.Scope{InstallationID: "installation"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*AgentUseRequirements)
	}{
		{"sensitive export", func(v *AgentUseRequirements) {
			v.Requirements = append(v.Requirements, AgentUseRequirement{ResourceType: "agent_installation", ResourceID: v.InstallationID, Action: "history.export", DataScope: DataScope{Type: "approved_organization"}})
		}},
		{"management", func(v *AgentUseRequirements) { v.Requirements[0].Action = "model.configure" }},
		{"all resources", func(v *AgentUseRequirements) { v.Requirements[0].ResourceID = "*" }},
		{"shared memory", func(v *AgentUseRequirements) {
			v.Requirements = append(v.Requirements, AgentUseRequirement{ResourceType: "memory", ResourceID: "memory", Action: "memory.read", DataScope: DataScope{Type: "approved_organization"}})
		}},
		{"child Agent rights", func(v *AgentUseRequirements) {
			v.Requirements = append(v.Requirements, AgentUseRequirement{ResourceType: "agent_installation", ResourceID: "child-installation", Action: "agent.delegate", DataScope: DataScope{Type: "approved_organization"}})
		}},
		{"duplicate", func(v *AgentUseRequirements) { v.Requirements = append(v.Requirements, v.Requirements[0]) }},
		{"invalid hash", func(v *AgentUseRequirements) { v.PolicyHash = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			value.Requirements = append([]AgentUseRequirement(nil), valid.Requirements...)
			tc.change(&value)
			if value.Seal() == nil {
				t.Fatal("unsafe requirements accepted")
			}
		})
	}
	reordered := valid
	reordered.Requirements = append([]AgentUseRequirement(nil), valid.Requirements...)
	slices.Reverse(reordered.Requirements)
	callerOrder := append([]AgentUseRequirement(nil), reordered.Requirements...)
	alias := reordered
	if alias.Seal() != nil || alias.Digest != valid.Digest || reordered.Requirements[0].ResourceType != callerOrder[0].ResourceType {
		t.Fatal("canonical requirement digest changed with order or mutated caller selections")
	}
	alias.DisplayName = "Translated display label"
	if alias.Seal() != nil || alias.Digest != valid.Digest {
		t.Fatal("display-only name invalidated company approval")
	}
}
