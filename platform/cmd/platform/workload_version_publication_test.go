package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type retainedVersionCatalog struct {
	resourceCatalogFixture
	versions map[string]catalog.Version
}

func (c retainedVersionCatalog) GetVersion(_ context.Context, id string) (catalog.Version, error) {
	v, ok := c.versions[id]
	if !ok {
		return catalog.Version{}, errors.New("version not published")
	}
	return v, c.failure
}

type retainedVersionPolicies struct {
	resourcePolicyFixture
	requested *[]string
	missing   string
}

func (p retainedVersionPolicies) Resolve(_ context.Context, s sharedkernel.Scope, version string) (policyasset.Snapshot, error) {
	if s.AgentVersionID != version || s.AgentID != "fixture" || s.InstallationID != "i" {
		return policyasset.Snapshot{}, identity.ErrInvalidResource
	}
	*p.requested = append(*p.requested, version)
	if p.missing == version {
		return policyasset.Snapshot{}, errors.New("historical policy unavailable")
	}
	return p.snapshot, p.failure
}

func TestRetainedWorkloadVersionsRequirePublishedSameDefinitionAndPinnedPolicies(t *testing.T) {
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"fixture","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://input","output":"schema://output","event":"schema://event","checkpoint":"schema://checkpoint"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	version := func(id, semver string) catalog.Version {
		raw := json.RawMessage(strings.Replace(string(manifest), "1.0.0", semver, 1))
		hash, err := catalog.VersionContentHash(raw, schema, schema)
		if err != nil {
			t.Fatal(err)
		}
		return catalog.Version{ID: id, DefinitionID: "def", SemanticVersion: semver, ManifestHash: hash, Manifest: raw, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionPublished, Revision: 1}
	}
	cat := retainedVersionCatalog{resourceCatalogFixture: resourceCatalogFixture{
		installation: catalog.Installation{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "fixture", VersionID: "new", Status: catalog.InstallationActive, Revision: 2},
		definition:   catalog.Definition{ID: "def", PublisherID: "p", AgentKey: "fixture", DisplayName: "Fixture", Description: "Version retention fixture", Status: catalog.DefinitionPublished, Revision: 1},
	}, versions: map[string]catalog.Version{"old": version("old", "1.0.0"), "new": version("new", "2.0.0")}}
	pol := resourcePolicyFixture{snapshot: policyasset.Snapshot{ModelProfileID: "model", PromptVersionID: "prompt", ToolPolicyID: "tools", MemoryPolicyID: "memory", KnowledgePolicyID: "knowledge", RuntimePolicyID: "runtime", Revision: 1, Hash: "fixture"}}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "executor", PrincipalType: "service_principal", InstallationID: "i", AgentInstanceID: "i", AgentID: "fixture", AgentVersionID: "new"}
	var requested []string
	resolver := publishedPermissionResourceResolver{catalog: cat, policies: retainedVersionPolicies{resourcePolicyFixture: pol, requested: &requested}}
	if err := resolver.ValidateWorkloadBindingVersions(context.Background(), scope, []string{"new", "old"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(requested, []string{"new", "old"}) {
		t.Fatal("old execution used current policy", requested)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*retainedVersionCatalog, *sharedkernel.Scope, *[]string)
	}{
		{"foreign-scope", func(_ *retainedVersionCatalog, s *sharedkernel.Scope, _ *[]string) { s.ApplicationID = "foreign" }},
		{"foreign-agent", func(_ *retainedVersionCatalog, s *sharedkernel.Scope, _ *[]string) { s.AgentID = "other" }},
		{"primary-not-current", func(_ *retainedVersionCatalog, s *sharedkernel.Scope, _ *[]string) { s.AgentVersionID = "old" }},
		{"duplicate", func(_ *retainedVersionCatalog, _ *sharedkernel.Scope, v *[]string) { *v = []string{"new", "new"} }},
		{"unknown-version", func(_ *retainedVersionCatalog, _ *sharedkernel.Scope, v *[]string) { *v = []string{"new", "absent"} }},
		{"unpublished-version", func(c *retainedVersionCatalog, _ *sharedkernel.Scope, _ *[]string) {
			v := c.versions["old"]
			v.Status = catalog.DefinitionDraft
			c.versions["old"] = v
		}},
		{"other-definition", func(c *retainedVersionCatalog, _ *sharedkernel.Scope, _ *[]string) {
			v := c.versions["old"]
			v.DefinitionID = "foreign"
			c.versions["old"] = v
		}},
		{"tampered-snapshot", func(c *retainedVersionCatalog, _ *sharedkernel.Scope, _ *[]string) {
			v := c.versions["old"]
			v.ManifestHash = strings.Repeat("b", 64)
			c.versions["old"] = v
		}},
		{"disabled-definition", func(c *retainedVersionCatalog, _ *sharedkernel.Scope, _ *[]string) {
			c.definition.Status = catalog.DefinitionDisabled
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := cat
			changed.versions = map[string]catalog.Version{"old": cat.versions["old"], "new": cat.versions["new"]}
			s, versions := scope, []string{"new", "old"}
			tc.mutate(&changed, &s, &versions)
			r := resolver
			r.catalog = changed
			if err := r.ValidateWorkloadBindingVersions(context.Background(), s, versions); err == nil {
				t.Fatal("invalid retained release accepted")
			}
		})
	}
	resolver.policies = retainedVersionPolicies{resourcePolicyFixture: pol, requested: &requested, missing: "old"}
	if err := resolver.ValidateWorkloadBindingVersions(context.Background(), scope, []string{"new", "old"}); err == nil {
		t.Fatal("missing original policy replaced with candidate policy")
	}
}
