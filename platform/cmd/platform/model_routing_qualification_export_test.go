package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/policyasset"
)

type qualificationExportFixture struct {
	reusePolicyFixture
	asset  policyasset.Asset
	getErr error
}

func (f *qualificationExportFixture) GetAsset(_ context.Context, scope policyasset.Scope, typ policyasset.AssetType, id string, rev uint64) (policyasset.Asset, error) {
	if f.getErr != nil {
		return policyasset.Asset{}, f.getErr
	}
	if scope != f.asset.Scope || typ != f.asset.Type || id != f.asset.ID || rev != f.asset.Revision {
		return policyasset.Asset{}, fmt.Errorf("not found")
	}
	return f.asset, nil
}

func crossWorkspaceQualificationFixture(t *testing.T) (modelRoutingPublicationValidator, policyasset.Scope, policyasset.ModelPolicy, *qualificationExportFixture) {
	t.Helper()
	v, oldDestination, p := qualificationReuseFixture()
	sourceScope := oldDestination
	sourceScope.AgentVersionID = "b6"
	policies := v.reusePolicies.(reusePolicyFixture)
	source := policies[sourceScope]
	destination := oldDestination
	destination.TenantID, destination.ApplicationID = "original-tenant", "original-app"
	current := policies[oldDestination]
	current.Knowledge.DocumentBindings = []policyasset.KnowledgeDocumentBinding{{}}
	current.Model.ContextCache = &policyasset.ContextCachePolicy{Version: "context-prefix/v2", Mode: "provider_prefix", Isolation: "session", UnsupportedModelBehavior: "prepare_prefix"}
	p = current.Model
	p.ModelVersionID = "large"
	p.Routing = &policyasset.ModelRoutingPolicy{Version: "model-routing/v1", SimpleMaxInputTokens: 256, ComplexMinInputTokens: 1024, SimpleMaxOutputTokens: 128, MaxEstimatedMicros: 100000,
		Candidates: []policyasset.ModelRouteCandidate{
			{ModelVersionID: "small", PriceVersionID: "small-price", CapabilitySHA256: strings.Repeat("1", 64), QualityEvidenceID: "small-eval", QualityEvidenceSHA256: strings.Repeat("2", 64), MaxComplexity: "simple"},
			{ModelVersionID: "large", PriceVersionID: "large-price", CapabilitySHA256: strings.Repeat("3", 64), QualityEvidenceID: "large-eval", QualityEvidenceSHA256: strings.Repeat("4", 64), MaxComplexity: "complex"},
		}}
	sourcePolicy := p
	sourcePolicy.ContextCache = nil
	sourceRouting := *p.Routing
	sourceRouting.Candidates = append([]policyasset.ModelRouteCandidate(nil), p.Routing.Candidates...)
	sourcePolicy.Routing = &sourceRouting
	source.Model = sourcePolicy
	sourceRouting.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(source)
	profile := policyasset.RoutingQualificationProfileSHA256(source)
	reuse := &policyasset.ModelRouteQualificationReuse{Version: "reviewed-routing-qualification-reuse/v2", SourceAgentVersionID: "b6",
		SourceExecutionContextSHA256: sourceRouting.ExecutionContextSHA256, SourceArtifactDigest: "sha256:" + strings.Repeat("b", 64), TargetArtifactDigest: "sha256:" + strings.Repeat("c", 64),
		BehaviorContextSHA256: policyasset.RoutingBehaviorContextSHA256(source), FrozenDatasetManifestSHA256: strings.Repeat("d", 64), ChangeReviewSHA256: strings.Repeat("e", 64), RegressionEvidenceSHA256: strings.Repeat("f", 64)}
	sourceRouting.QualificationExports = []policyasset.ModelRouteQualificationExport{{TargetScope: destination, TargetArtifactDigest: reuse.TargetArtifactDigest, QualificationProfileSHA256: profile}}
	raw, err := json.Marshal(sourcePolicy)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	f := &qualificationExportFixture{reusePolicyFixture: reusePolicyFixture{sourceScope: source, destination: current}, asset: policyasset.Asset{ID: "approved-source-export", Scope: sourceScope, Type: policyasset.AssetModel, Revision: 2, Status: policyasset.AssetPublished, Content: raw, Hash: hex.EncodeToString(hash[:]), CreatedBy: "source-owner"}}
	reuse.Source = &policyasset.ModelRouteQualificationSource{Scope: sourceScope, ModelAsset: policyasset.AssetRef{ID: f.asset.ID, Revision: f.asset.Revision}, ContentSHA256: f.asset.Hash, QualificationProfileSHA256: profile}
	p.Routing.QualificationReuse = reuse
	current.Model = p
	p.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(current)
	f.reusePolicyFixture[destination] = current
	versions := v.reuseCatalog.(reuseCatalogFixture)
	target := versions["b7"]
	target.DefinitionID = "original-workspace-definition"
	versions["b7"] = target
	v.reusePolicies = f
	if p.ValidateRouting() != nil || sourcePolicy.ValidateRouting() != nil {
		t.Fatal("invalid fixture routing")
	}
	return v, destination, p, f
}

func TestQualificationExportUsesApprovedSourceWithoutRelabellingRuns(t *testing.T) {
	v, scope, p, _ := crossWorkspaceQualificationFixture(t)
	got, err := v.reviewedQualificationTarget(context.Background(), scope, p)
	if err != nil || got.AgentVersionID != "b6" || got.ExecutionContextSHA256 != p.Routing.QualificationReuse.SourceExecutionContextSHA256 {
		t.Fatal("source provenance lost", got, err)
	}
	actual := routingQualificationScope(scope, p)
	if actual.TenantID != "t" || actual.ApplicationID != "a" || actual.TenantID == scope.TenantID {
		t.Fatal("native evaluation used destination instead of actual source", actual)
	}
	source := p.Routing.QualificationReuse.Source.Scope
	f := v.reusePolicies.(*qualificationExportFixture)
	if err := v.validateQualificationExports(context.Background(), source, f.reusePolicyFixture[source].Model); err != nil {
		t.Fatal("source export not independently publishable", err)
	}
}

func TestQualificationExportRejectsMissingApprovalAndBehaviorDrift(t *testing.T) {
	for _, name := range []string{"downgrade", "no-source", "wrong-source", "draft", "missing-owner", "bad-hash", "tampered-bytes", "missing-grant", "wrong-destination", "wrong-artifact", "profile", "prompt", "temperature", "candidate", "tier", "reasoning", "inherited-reasoning", "different-contract", "no-export-reader", "retention-widening"} {
		t.Run(name, func(t *testing.T) {
			v, scope, p, f := crossWorkspaceQualificationFixture(t)
			r := p.Routing.QualificationReuse
			var exported policyasset.ModelPolicy
			if err := json.Unmarshal(f.asset.Content, &exported); err != nil {
				t.Fatal(err)
			}
			repack := false
			switch name {
			case "downgrade":
				r.Version = "reviewed-routing-qualification-reuse/v1"
			case "retention-widening":
				r.Source.MaxEvidenceAgeSeconds = 7 * 86400
			case "no-source":
				r.Source = nil
			case "wrong-source":
				r.Source.Scope.TenantID = "foreign"
			case "draft":
				f.asset.Status = policyasset.AssetDraft
			case "missing-owner":
				f.asset.CreatedBy = ""
			case "bad-hash":
				f.asset.Hash = strings.Repeat("0", 64)
			case "tampered-bytes":
				f.asset.Content = append(f.asset.Content, ' ')
			case "missing-grant":
				exported.Routing.QualificationExports = nil
				repack = true
			case "wrong-destination":
				exported.Routing.QualificationExports[0].TargetScope.ApplicationID = "foreign"
				repack = true
			case "wrong-artifact":
				exported.Routing.QualificationExports[0].TargetArtifactDigest = "sha256:" + strings.Repeat("0", 64)
				repack = true
			case "profile":
				r.Source.QualificationProfileSHA256 = strings.Repeat("0", 64)
			case "prompt":
				s := f.reusePolicyFixture[scope]
				s.Prompt.Template += "changed"
				f.reusePolicyFixture[scope] = s
				s.Model = p
				p.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(s)
			case "temperature":
				p.Temperature = 0.7
			case "candidate":
				p.Routing.Candidates[0].QualityEvidenceID = "unapproved"
			case "tier":
				p.Routing.Candidates[0].MaxComplexity = "complex"
			case "reasoning":
				p.Routing.Candidates[0].Reasoning = &policyasset.ModelRouteReasoning{Mode: "enabled", Effort: "high"}
			case "inherited-reasoning":
				p.ReasoningMode, p.ReasoningEffort = "enabled", "high"
			case "different-contract":
				versions := v.reuseCatalog.(reuseCatalogFixture)
				a := versions["b7"]
				a.InputSchema = json.RawMessage(`{"type":"array"}`)
				versions["b7"] = a
			case "no-export-reader":
				v.reusePolicies = f.reusePolicyFixture
			}
			if repack {
				f.asset.Content, _ = json.Marshal(exported)
				h := sha256.Sum256(f.asset.Content)
				f.asset.Hash = hex.EncodeToString(h[:])
				r.Source.ContentSHA256 = f.asset.Hash
			}
			if _, err := v.reviewedQualificationTarget(context.Background(), scope, p); err == nil {
				t.Fatal("unapproved source or drift accepted")
			}
		})
	}
}

func TestQualificationExportsCannotBeChainedOrPointAtDraftArtifacts(t *testing.T) {
	for _, name := range []string{"chained", "wrong-profile", "wrong-artifact", "draft", "other-agent"} {
		t.Run(name, func(t *testing.T) {
			v, _, p, f := crossWorkspaceQualificationFixture(t)
			scope := p.Routing.QualificationReuse.Source.Scope
			source := f.reusePolicyFixture[scope].Model
			switch name {
			case "chained":
				source.Routing.QualificationReuse = p.Routing.QualificationReuse
			case "wrong-profile":
				source.Routing.QualificationExports[0].QualificationProfileSHA256 = strings.Repeat("0", 64)
			case "wrong-artifact":
				source.Routing.QualificationExports[0].TargetArtifactDigest = "sha256:" + strings.Repeat("0", 64)
			case "draft":
				versions := v.reuseCatalog.(reuseCatalogFixture)
				a := versions["b7"]
				a.Status = "draft"
				versions["b7"] = a
			case "other-agent":
				source.Routing.QualificationExports[0].TargetScope.AgentID = "other"
			}
			if v.validateQualificationExports(context.Background(), scope, source) == nil {
				t.Fatal("invalid source export accepted")
			}
		})
	}
}

func TestQualificationExportBoundedDestinationList(t *testing.T) {
	_, _, p, f := crossWorkspaceQualificationFixture(t)
	source := f.reusePolicyFixture[p.Routing.QualificationReuse.Source.Scope].Model
	grant := source.Routing.QualificationExports[0]
	source.Routing.QualificationExports = []policyasset.ModelRouteQualificationExport{grant, grant}
	if source.ValidateRouting() == nil {
		t.Fatal("duplicate destinations accepted")
	}
	source.Routing.QualificationExports = nil
	for i := 0; i < 17; i++ {
		g := grant
		g.TargetScope.ApplicationID = fmt.Sprintf("app-%d", i)
		source.Routing.QualificationExports = append(source.Routing.QualificationExports, g)
	}
	if source.ValidateRouting() == nil {
		t.Fatal("unbounded exports accepted")
	}
}
