package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"strings"
	"testing"
)

type resourceCatalogFixture struct {
	installation catalog.Installation
	version      catalog.Version
	definition   catalog.Definition
	failure      error
}

func (r resourceCatalogFixture) GetInstallation(context.Context, string) (catalog.Installation, error) {
	return r.installation, r.failure
}
func (r resourceCatalogFixture) GetVersion(context.Context, string) (catalog.Version, error) {
	return r.version, r.failure
}
func (r resourceCatalogFixture) GetDefinition(context.Context, string) (catalog.Definition, error) {
	return r.definition, r.failure
}

type resourcePolicyFixture struct {
	snapshot policyasset.Snapshot
	failure  error
}

func (r resourcePolicyFixture) Resolve(context.Context, sharedkernel.Scope, string) (policyasset.Snapshot, error) {
	return r.snapshot, r.failure
}

func TestPublishedPermissionResourcesRequireCurrentInstallationAndPolicy(t *testing.T) {
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"fixture","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://input","output":"schema://output","event":"schema://event","checkpoint":"schema://checkpoint"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	cat := resourceCatalogFixture{installation: catalog.Installation{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "fixture", VersionID: "v", Status: catalog.InstallationActive, Revision: 1}, definition: catalog.Definition{ID: "def", PublisherID: "p", AgentKey: "fixture", DisplayName: "Fixture", Description: "Resource fixture", Status: catalog.DefinitionPublished, Revision: 1}, version: catalog.Version{ID: "v", DefinitionID: "def", SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionPublished, Revision: 1}}
	pol := resourcePolicyFixture{snapshot: policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tool-policy", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge-policy", RuntimePolicyID: "runtime", Revision: 1, Hash: "fixture", Tool: policyasset.ToolPolicy{AllowedTools: []string{"tool"}}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"knowledge"}}}}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", AgentInstanceID: "i", InstallationID: "i"}
	t.Run("complete use package pins material without disclosing it", func(t *testing.T) {
		complete := pol
		complete.snapshot.Model = policyasset.ModelPolicy{Provider: "fixture-provider", Model: "fixture-model", MaxTokens: 64}
		complete.snapshot.Prompt = policyasset.PromptPolicy{TemplateHash: "approved-prompt", Template: "fixture-approved-private-template"}
		complete.snapshot.Memory = policyasset.MemoryPolicy{MaxEntries: 10}
		complete.snapshot.Runtime = policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 30, LeaseSeconds: 30}
		resolver := publishedPermissionResourceResolver{catalog: cat, policies: complete}
		pack, err := resolver.ResolveAgentUsePackage(context.Background(), scope)
		if err != nil || pack.AgentVersionID != "v" || len(pack.Resources) != 11 {
			t.Fatal("published dependency package was incomplete", err)
		}
		raw, err := json.Marshal(pack)
		if err != nil || strings.Contains(string(raw), complete.snapshot.Prompt.Template) || strings.Contains(string(raw), "fixture-provider") || strings.Contains(string(raw), "template_hash") {
			t.Fatal("package metadata disclosed policy contents", err)
		}
		complete.snapshot.Prompt.Template = "changed-approved-private-template"
		resolver.policies = complete
		changed, err := resolver.ResolveAgentUsePackage(context.Background(), scope)
		if err != nil || changed.Digest == pack.Digest {
			t.Fatal("changed policy material reused an old review despite an unchanged opaque hash label", err)
		}
		complete.snapshot.Runtime.AllowedSkills = []string{"skill"}
		resolver.policies = complete
		if _, err := resolver.ResolveAgentUsePackage(context.Background(), scope); !errors.Is(err, identity.ErrInvalidResource) {
			t.Fatal("unavailable Skill was advertised as a usable dependency", err)
		}
	})
	availability := func(c resourceCatalogFixture, s sharedkernel.Scope) (string, error) {
		return (publishedPermissionResourceResolver{catalog: c, policies: pol}).ResolvePermissionRunAvailability(context.Background(), s)
	}
	if reason, err := availability(cat, scope); err != nil || reason != "" {
		t.Fatal("published installation unavailable", reason, err)
	}
	for _, tc := range []struct {
		mutate func(*resourceCatalogFixture)
		reason string
	}{
		{func(c *resourceCatalogFixture) { c.version.Status = catalog.DefinitionDraft }, "RESOURCE_NOT_PUBLISHED"},
		{func(c *resourceCatalogFixture) { c.definition.Status = catalog.DefinitionDraft }, "RESOURCE_NOT_PUBLISHED"},
		{func(c *resourceCatalogFixture) { c.installation.Status = catalog.InstallationSuspended }, "RESOURCE_UNAVAILABLE"},
		{func(c *resourceCatalogFixture) { c.definition.Status = catalog.DefinitionDisabled }, "RESOURCE_UNAVAILABLE"},
	} {
		changed := cat
		tc.mutate(&changed)
		if reason, err := availability(changed, scope); err != nil || reason != tc.reason {
			t.Fatal("incorrect publication reason", reason, err)
		}
	}
	foreign := scope
	foreign.ApplicationID = "other"
	if _, err := availability(cat, foreign); !errors.Is(err, identity.ErrInvalidResource) {
		t.Fatal("publication state disclosed outside installation scope", err)
	}
	broken := cat
	broken.version.ManifestHash = "invalid"
	if _, err := availability(broken, scope); err == nil {
		t.Fatal("status alone treated as a valid published snapshot")
	}
	for _, typ := range []string{"model", "tool", "knowledge", "memory"} {
		resolver := publishedPermissionResourceResolver{catalog: cat, policies: pol}
		actual, err := resolver.ResolvePermissionResource(context.Background(), scope, typ, typ)
		if err != nil || actual.InstallationID != "i" || actual.Type != typ {
			t.Fatal(actual, err)
		}
		if _, err := resolver.ResolvePermissionResource(context.Background(), scope, typ, "unknown"); !errors.Is(err, identity.ErrInvalidResource) {
			t.Fatal("unpublished policy resource accepted", err)
		}
	}
	workload, err := (publishedPermissionResourceResolver{catalog: cat, policies: pol}).ResolvePermissionResource(context.Background(), scope, "agent_installation", "i")
	if err != nil || workload.AgentID != "fixture" || workload.AgentVersionID != "v" || workload.InstallationID != "i" {
		t.Fatal("workload target lost published identity", workload, err)
	}
	for _, mutate := range []func(*resourceCatalogFixture){func(c *resourceCatalogFixture) { c.installation.ApplicationID = "other" }, func(c *resourceCatalogFixture) { c.installation.Status = catalog.InstallationSuspended }, func(c *resourceCatalogFixture) { c.version.Status = catalog.DefinitionDraft }, func(c *resourceCatalogFixture) { c.definition.AgentKey = "other" }, func(c *resourceCatalogFixture) { c.definition.Status = catalog.DefinitionDisabled }} {
		invalid := cat
		mutate(&invalid)
		if _, err := (publishedPermissionResourceResolver{catalog: invalid, policies: pol}).ResolvePermissionResource(context.Background(), scope, "knowledge", "knowledge"); !errors.Is(err, identity.ErrInvalidResource) {
			t.Fatal("invalid catalog accepted", err)
		}
	}
	failure := errors.New("source unavailable")
	cat.failure = failure
	if _, err := (publishedPermissionResourceResolver{catalog: cat, policies: pol}).ResolvePermissionResource(context.Background(), scope, "model", "model"); !errors.Is(err, failure) {
		t.Fatal("catalog failure swallowed", err)
	}
	cat.failure = nil
	pol.failure = failure
	if _, err := (publishedPermissionResourceResolver{catalog: cat, policies: pol}).ResolvePermissionResource(context.Background(), scope, "model", "model"); !errors.Is(err, failure) {
		t.Fatal("policy failure swallowed", err)
	}
}
