package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type requirementsSkillFixture struct{ available bool }

func (f requirementsSkillFixture) PublishedSkillAvailable(context.Context, sharedkernel.Scope, string) (bool, error) {
	return f.available, nil
}

type requirementsPublicationSwapFixture struct {
	resourceCatalogFixture
	reads  int
	change func(*catalog.Installation)
}

func (f *requirementsPublicationSwapFixture) GetInstallation(context.Context, string) (catalog.Installation, error) {
	f.reads++
	value := f.installation
	if f.reads > 1 {
		if f.change == nil {
			value.VersionID = "unapproved-next-version"
		} else {
			f.change(&value)
		}
	}
	return value, nil
}

func TestPublishedAgentUseRequirementsPinActualCapabilitiesAndPublication(t *testing.T) {
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"fixture","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://input","output":"schema://output","event":"schema://event","checkpoint":"schema://checkpoint"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	cat := resourceCatalogFixture{installation: catalog.Installation{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "fixture", VersionID: "v", Status: catalog.InstallationActive, Revision: 1},
		definition: catalog.Definition{ID: "def", PublisherID: "p", AgentKey: "fixture", DisplayName: "Fixture", Description: "Resource fixture", Status: catalog.DefinitionPublished, Revision: 1},
		version:    catalog.Version{ID: "v", DefinitionID: "def", SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionPublished, Revision: 1}}
	pol := resourcePolicyFixture{snapshot: policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tool-policy", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge-policy", RuntimePolicyID: "runtime", Revision: 1, Hash: strings.Repeat("b", 64),
		Model:  policyasset.ModelPolicy{Provider: "fixture-provider", Model: "fixture-model", MaxTokens: 512, EmbeddingModelVersionID: "embedding-version", EmbeddingProvider: "fixture-provider", EmbeddingModel: "fixture-embedding"},
		Prompt: policyasset.PromptPolicy{TemplateHash: "prompt-hash"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"tool"}, RequireConfirmation: []string{"tool"}},
		Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"knowledge"}}, Memory: policyasset.MemoryPolicy{MaxEntries: 20, SemanticEnabled: true},
		Runtime: policyasset.RuntimePolicy{MaxAttempts: 2, TaskTimeoutSeconds: 30, LeaseSeconds: 60, AllowedSkills: []string{"skill"}, Delegation: &policyasset.AgentDelegationPolicy{AllowedAgentIDs: []string{"child-agent"}, TaskTypes: []string{"review"}, MaxDepth: 1, MaxChildren: 2}}}}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "root", PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i"}
	resolver := publishedPermissionResourceResolver{catalog: cat, policies: pol, skills: requirementsSkillFixture{available: true}}
	result, err := resolver.ResolveAgentUseRequirements(context.Background(), scope)
	if err != nil || result.AgentVersionID != "v" || result.PolicyHash != pol.snapshot.Hash || result.Digest == "" {
		t.Fatal("actual immutable requirements unavailable", err)
	}
	seen := map[string]bool{}
	for _, item := range result.Requirements {
		seen[item.Action] = true
		if item.ResourceType == "memory" && item.DataScope.Type != "owner" || item.ResourceType == "tool" && !item.RequiresConfirmation || item.ResourceType == "agent_installation" && item.ResourceID != "i" {
			t.Fatal("published limits or source installation changed", item)
		}
	}
	for _, action := range []string{"model.generate", "model.embed", "tool.invoke", "knowledge.search", "memory.read", "memory.write", "skill.load", "agent.delegate"} {
		if !seen[action] {
			t.Fatal("declared prerequisite missing", action)
		}
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "fixture-provider") || strings.Contains(string(raw), "fixture-model") || strings.Contains(string(raw), "child-agent") {
		t.Fatal("requirement summary disclosed provider configuration or granted child Agent access")
	}
	resolver.skills = requirementsSkillFixture{available: false}
	if _, err := resolver.ResolveAgentUseRequirements(context.Background(), scope); err != identity.ErrInvalidResource {
		t.Fatal("unpublished Skill included in complete use", err)
	}
	resolver.skills = requirementsSkillFixture{available: true}
	resolver.catalog = &requirementsPublicationSwapFixture{resourceCatalogFixture: cat}
	if _, err := resolver.ResolveAgentUseRequirements(context.Background(), scope); err != identity.ErrIdentityConflict {
		t.Fatal("installation switched publication during dependency resolution", err)
	}
	for _, change := range []func(*catalog.Installation){
		func(v *catalog.Installation) { v.Status = catalog.InstallationSuspended },
		func(v *catalog.Installation) { v.TenantID = "foreign-company" },
		func(v *catalog.Installation) { v.DepartmentID = "foreign-department" },
		func(v *catalog.Installation) { v.ApplicationID = "foreign-entry" },
	} {
		resolver.catalog = &requirementsPublicationSwapFixture{resourceCatalogFixture: cat, change: change}
		if _, err := resolver.ResolveAgentUseRequirements(context.Background(), scope); err != identity.ErrIdentityConflict {
			t.Fatal("installation availability or ownership changed during dependency resolution", err)
		}
	}
	resolver.catalog = cat
	pol.snapshot.Memory.MaxEntries = 0
	resolver.policies = pol
	if _, err := resolver.ResolveAgentUseRequirements(context.Background(), scope); err != identity.ErrInvalidResource {
		t.Fatal("incomplete published behavior reported as usable", err)
	}
}
