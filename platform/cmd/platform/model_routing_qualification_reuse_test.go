package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/policyasset"
)

type reuseCatalogFixture map[string]catalog.Version

func (f reuseCatalogFixture) GetVersion(_ context.Context, id string) (catalog.Version, error) {
	v, ok := f[id]
	if !ok {
		return catalog.Version{}, fmt.Errorf("not found")
	}
	return v, nil
}

type reusePolicyFixture map[policyasset.Scope]policyasset.Snapshot

func (f reusePolicyFixture) GetSnapshot(_ context.Context, s policyasset.Scope) (policyasset.Snapshot, error) {
	v, ok := f[s]
	if !ok {
		return policyasset.Snapshot{}, fmt.Errorf("not found")
	}
	return v, nil
}

func qualificationReuseFixture() (modelRoutingPublicationValidator, policyasset.Scope, policyasset.ModelPolicy) {
	scope := policyasset.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "qa", AgentVersionID: "b7"}
	oldScope := scope
	oldScope.AgentVersionID = "b6"
	source := policyasset.Snapshot{PromptVersionID: "old-prompt", ToolPolicyID: "old-tool", MemoryPolicyID: "old-memory", KnowledgePolicyID: "old-knowledge", RuntimePolicyID: "old-runtime",
		Prompt: policyasset.PromptPolicy{Template: "unchanged", TemplateHash: strings.Repeat("a", 64)},
		Model:  policyasset.ModelPolicy{MaxInputTokens: 1024, MaxTokens: 512, AllowExternal: true}}
	current := source
	current.PromptVersionID = "new-prompt"
	current.ToolPolicyID = "new-tool"
	current.MemoryPolicyID = "new-memory"
	current.KnowledgePolicyID = "new-knowledge"
	current.RuntimePolicyID = "new-runtime"
	p := current.Model
	r := &policyasset.ModelRouteQualificationReuse{Version: "reviewed-routing-qualification-reuse/v1", SourceAgentVersionID: "b6",
		SourceExecutionContextSHA256: policyasset.RoutingExecutionContextSHA256(source), SourceArtifactDigest: "sha256:" + strings.Repeat("b", 64),
		TargetArtifactDigest: "sha256:" + strings.Repeat("c", 64), BehaviorContextSHA256: policyasset.RoutingBehaviorContextSHA256(source),
		FrozenDatasetManifestSHA256: strings.Repeat("d", 64), ChangeReviewSHA256: strings.Repeat("e", 64), RegressionEvidenceSHA256: strings.Repeat("f", 64)}
	p.Routing = &policyasset.ModelRoutingPolicy{Version: "model-routing/v1", ExecutionContextSHA256: policyasset.RoutingExecutionContextSHA256(current), QualificationReuse: r}
	versions := reuseCatalogFixture{}
	for _, id := range []string{"b6", "b7"} {
		digest := r.SourceArtifactDigest
		if id == "b7" {
			digest = r.TargetArtifactDigest
		}
		versions[id] = catalog.Version{ID: id, DefinitionID: "qa-def", ArtifactDigest: digest, Status: catalog.DefinitionPublished, ApprovedBy: "publisher",
			Manifest: json.RawMessage(`{"agent_id":"qa","version":"` + id + `","capabilities":["answer"]}`), InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`)}
	}
	return modelRoutingPublicationValidator{reuseCatalog: versions, reusePolicies: reusePolicyFixture{scope: current, oldScope: source}}, scope, p
}

func TestReviewedRoutingQualificationReuseRetainsActualSourceIdentity(t *testing.T) {
	v, scope, p := qualificationReuseFixture()
	got, err := v.reviewedQualificationTarget(context.Background(), scope, p)
	if err != nil || got.AgentID != scope.AgentID || got.AgentVersionID != "b6" || got.ExecutionContextSHA256 != p.Routing.QualificationReuse.SourceExecutionContextSHA256 {
		t.Fatalf("source results were not retained: %+v %v", got, err)
	}
	p.Routing.QualificationReuse = nil
	got, err = v.reviewedQualificationTarget(context.Background(), scope, p)
	if err != nil || got.AgentVersionID != "b7" || got.ExecutionContextSHA256 != p.Routing.ExecutionContextSHA256 {
		t.Fatal("ordinary qualification changed", got, err)
	}
}

func TestReviewedRoutingQualificationReuseRejectsDrift(t *testing.T) {
	for _, name := range []string{"missing-review", "missing-regression", "missing-dataset", "source-artifact", "target-artifact", "same-version", "no-catalog", "no-policies", "source-unpublished", "target-unpublished", "source-not-approved", "different-agent", "missing-manifest-agent", "different-definition", "input-schema", "output-schema", "manifest-capability", "missing-source", "foreign-scope", "source-context", "target-context", "behavior", "prompt", "embedding", "output-budget"} {
		t.Run(name, func(t *testing.T) {
			v, scope, p := qualificationReuseFixture()
			r := p.Routing.QualificationReuse
			versions := v.reuseCatalog.(reuseCatalogFixture)
			policies := v.reusePolicies.(reusePolicyFixture)
			oldScope := scope
			oldScope.AgentVersionID = "b6"
			switch name {
			case "missing-review":
				r.ChangeReviewSHA256 = ""
			case "missing-regression":
				r.RegressionEvidenceSHA256 = ""
			case "missing-dataset":
				r.FrozenDatasetManifestSHA256 = ""
			case "source-artifact":
				r.SourceArtifactDigest = "sha256:" + strings.Repeat("0", 64)
			case "target-artifact":
				r.TargetArtifactDigest = "sha256:" + strings.Repeat("0", 64)
			case "same-version":
				r.SourceAgentVersionID = "b7"
			case "no-catalog":
				v.reuseCatalog = nil
			case "no-policies":
				v.reusePolicies = nil
			case "source-unpublished":
				a := versions["b6"]
				a.Status = catalog.DefinitionDraft
				versions["b6"] = a
			case "target-unpublished":
				a := versions["b7"]
				a.Status = catalog.DefinitionDraft
				versions["b7"] = a
			case "source-not-approved":
				a := versions["b6"]
				a.ApprovedBy = ""
				versions["b6"] = a
			case "different-agent":
				a := versions["b7"]
				a.Manifest = json.RawMessage(`{"agent_id":"other","version":"b7","capabilities":["answer"]}`)
				versions["b7"] = a
			case "missing-manifest-agent":
				a := versions["b6"]
				a.Manifest = json.RawMessage(`{"version":"b6","capabilities":["answer"]}`)
				versions["b6"] = a
			case "different-definition":
				a := versions["b7"]
				a.DefinitionID = "other"
				versions["b7"] = a
			case "input-schema":
				a := versions["b7"]
				a.InputSchema = json.RawMessage(`{"type":"array"}`)
				versions["b7"] = a
			case "output-schema":
				a := versions["b7"]
				a.OutputSchema = json.RawMessage(`{"type":"array"}`)
				versions["b7"] = a
			case "manifest-capability":
				a := versions["b7"]
				a.Manifest = json.RawMessage(`{"agent_id":"qa","version":"b7","capabilities":["different"]}`)
				versions["b7"] = a
			case "missing-source":
				delete(policies, oldScope)
			case "foreign-scope":
				scope.ApplicationID = "foreign"
			case "source-context":
				r.SourceExecutionContextSHA256 = strings.Repeat("0", 64)
			case "target-context":
				p.Routing.ExecutionContextSHA256 = strings.Repeat("0", 64)
			case "behavior":
				r.BehaviorContextSHA256 = strings.Repeat("0", 64)
			case "prompt":
				s := policies[scope]
				s.Prompt.Template = "changed"
				policies[scope] = s
				p.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(s)
			case "embedding":
				p.EmbeddingModelVersionID = "other-index-embedding"
				s := policies[scope]
				s.Model = p
				p.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(s)
			case "output-budget":
				p.MaxTokens++
				s := policies[scope]
				s.Model = p
				p.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(s)
			}
			if _, err := v.reviewedQualificationTarget(context.Background(), scope, p); err == nil {
				t.Fatal("unreviewed drift accepted")
			}
		})
	}
}
