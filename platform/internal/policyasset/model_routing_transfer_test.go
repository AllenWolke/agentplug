package policyasset

import (
	"strings"
	"testing"
)

func TestQualificationProfileAllowsMembershipChangeButPinsBehavior(t *testing.T) {
	source := validSnapshot()
	source.Model.ContextCache = nil
	before := RoutingQualificationProfileSHA256(source)
	if before == "" {
		t.Fatal("empty profile")
	}
	changed := source
	changed.PromptVersionID += "-release"
	changed.Knowledge.DocumentBindings = []KnowledgeDocumentBinding{{}}
	changed.Knowledge.AllowedScopes = []string{"destination-reviewed-knowledge"}
	changed.Model.ContextCache = &ContextCachePolicy{Version: "context-prefix/v2", Mode: "provider_prefix", Isolation: "session", UnsupportedModelBehavior: "prepare_prefix"}
	if RoutingExecutionContextSHA256(source) == RoutingExecutionContextSHA256(changed) || before != RoutingQualificationProfileSHA256(changed) {
		t.Fatal("full provenance must differ while the applicability profile is retained")
	}
	for name, mutate := range map[string]func(*Snapshot){
		"prompt":      func(s *Snapshot) { s.Prompt.Template += "changed" },
		"tools":       func(s *Snapshot) { s.Tool.AllowedTools = []string{"different"} },
		"memory":      func(s *Snapshot) { s.Memory.MaxEntries++ },
		"runtime":     func(s *Snapshot) { s.Runtime.TaskTimeoutSeconds++ },
		"evidence":    func(s *Snapshot) { s.Knowledge.RequireReferences = !s.Knowledge.RequireReferences },
		"replay":      func(s *Snapshot) { s.Knowledge.AllowReplay = !s.Knowledge.AllowReplay },
		"degradation": func(s *Snapshot) { s.Knowledge.AllowPartialDegraded = !s.Knowledge.AllowPartialDegraded },
		"embedding":   func(s *Snapshot) { s.Model.EmbeddingModelVersionID += "changed" },
		"budget":      func(s *Snapshot) { s.Model.BudgetCents++ },
		"output":      func(s *Snapshot) { s.Model.MaxTokens++ },
		"temperature": func(s *Snapshot) { s.Model.Temperature += 0.1 },
		"rule":        func(s *Snapshot) { s.RuleBundleChecksum += "changed"; s.Rule.Checksum += "changed" },
	} {
		t.Run(name, func(t *testing.T) {
			s := source
			mutate(&s)
			if before == RoutingQualificationProfileSHA256(s) {
				t.Fatal("behavior drift accepted")
			}
		})
	}
	changed.Model.ContextCache.Mode = "semantic"
	if RoutingQualificationProfileSHA256(changed) != "" {
		t.Fatal("unsupported cache normalized")
	}
}

func TestQualificationTransferRequiresVersionedFiniteSourceAndDestination(t *testing.T) {
	hash := strings.Repeat("a", 64)
	scope := Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentID: "agent", AgentVersionID: "source"}
	ref := ModelRouteQualificationSource{Scope: scope, ModelAsset: AssetRef{ID: "source-model", Revision: 2}, ContentSHA256: hash, QualificationProfileSHA256: hash}
	grant := ModelRouteQualificationExport{TargetScope: scope, TargetArtifactDigest: "sha256:" + hash, QualificationProfileSHA256: hash}
	if ref.Validate() != nil || grant.Validate() != nil {
		t.Fatal("valid references rejected")
	}
	for _, bad := range []ModelRouteQualificationSource{
		{Scope: scope, ModelAsset: AssetRef{ID: "source-model", Revision: 1}, ContentSHA256: hash, QualificationProfileSHA256: hash},
		{Scope: scope, ModelAsset: ref.ModelAsset, ContentSHA256: "", QualificationProfileSHA256: hash},
		{ModelAsset: ref.ModelAsset, ContentSHA256: hash, QualificationProfileSHA256: hash},
	} {
		if bad.Validate() == nil {
			t.Fatal("invalid source accepted")
		}
	}
	grant.TargetScope.TenantID = "*"
	// Scope wildcard must not be interpreted as a permission pattern. Existing
	// scope validation treats IDs literally; the export lookup also uses equality.
	grant.TargetArtifactDigest = "sha256:short"
	if grant.Validate() == nil {
		t.Fatal("malformed artifact accepted")
	}
}

func TestQualificationAgeRequiresBoundedReviewedSourceGrant(t *testing.T) {
	hash := strings.Repeat("a", 64)
	scope := Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentID: "agent", AgentVersionID: "version"}
	grant := ModelRouteQualificationExport{TargetScope: scope, TargetArtifactDigest: "sha256:" + hash, QualificationProfileSHA256: hash}
	ref := ModelRouteQualificationSource{Scope: scope, ModelAsset: AssetRef{ID: "source", Revision: 2}, ContentSHA256: hash, QualificationProfileSHA256: hash}
	for _, seconds := range []int64{0, 86400, 7 * 86400} {
		grant.MaxEvidenceAgeSeconds, ref.MaxEvidenceAgeSeconds = seconds, seconds
		if grant.Validate() != nil || ref.Validate() != nil || grant.EvidenceMaxAgeSeconds() < 86400 {
			t.Fatal("valid age policy rejected")
		}
	}
	for _, seconds := range []int64{-1, 1, 86399, 7*86400 + 1} {
		grant.MaxEvidenceAgeSeconds, ref.MaxEvidenceAgeSeconds = seconds, seconds
		if grant.Validate() == nil || ref.Validate() == nil {
			t.Fatal("unbounded or invalid retained age accepted")
		}
	}
	var p ModelRoutingPolicy
	if p.QualificationEvidenceMaxAgeSeconds() != 86400 {
		t.Fatal("default gate changed")
	}
	grant.MaxEvidenceAgeSeconds = 7 * 86400
	p.QualificationExports = []ModelRouteQualificationExport{grant}
	if p.QualificationEvidenceMaxAgeSeconds() != 7*86400 {
		t.Fatal("reviewed source grant not applied")
	}
	grant.MaxEvidenceAgeSeconds = 0
	p.QualificationExports = append(p.QualificationExports, grant)
	if p.QualificationEvidenceMaxAgeSeconds() != 86400 {
		t.Fatal("most permissive destination widened other grants")
	}
}

func TestQualificationProfilePinsEmbeddingVersionAcrossCatalogAliasRename(t *testing.T) {
	source := validSnapshot()
	source.Model.EmbeddingModelVersionID = "immutable-embedding-version"
	source.Model.EmbeddingProvider = "source-provider-key"
	source.Model.EmbeddingModel = "fixed-index-embedding"
	profile := RoutingQualificationProfileSHA256(source)
	if profile == "" {
		t.Fatal("valid pinned embedding rejected")
	}
	target := source
	target.Model.EmbeddingProvider = "destination-provider-alias"
	if RoutingQualificationProfileSHA256(target) != profile || RoutingExecutionContextSHA256(target) == RoutingExecutionContextSHA256(source) {
		t.Fatal("catalog alias changed version identity or historical execution provenance")
	}
	target.Model.EmbeddingModelVersionID += "-different"
	if RoutingQualificationProfileSHA256(target) == profile {
		t.Fatal("different index embedding version accepted")
	}
	target = source
	target.Model.EmbeddingModel += "-different"
	if RoutingQualificationProfileSHA256(target) == profile {
		t.Fatal("different embedding model accepted")
	}
	target = source
	target.Model.EmbeddingModelVersionID = ""
	if RoutingQualificationProfileSHA256(target) != "" {
		t.Fatal("unversioned provider alias normalized")
	}
}

func TestContextPrefixPreparationFallbackIsExplicitAndDoesNotClaimSupport(t *testing.T) {
	for _, version := range []string{"context-prefix/v1", "context-prefix/v2"} {
		p := ModelPolicy{ContextCache: &ContextCachePolicy{Version: version, Mode: "provider_prefix", Isolation: "session"}}
		if version == "context-prefix/v2" {
			p.ContextCache.UnsupportedModelBehavior = "prepare_prefix"
		}
		if p.ValidateContextCache() != nil || !p.AllowsContextCacheMode("provider_prefix") || p.AllowsContextCacheMode("semantic") {
			t.Fatal("invalid capability boundary")
		}
		if p.AllowsContextCacheMode("") != (version == "context-prefix/v2") {
			t.Fatal("unsupported-model fallback is not opt-in")
		}
		p.ContextCache.UnsupportedModelBehavior = "invent_hits"
		if p.ValidateContextCache() == nil || p.AllowsContextCacheMode("provider_prefix") {
			t.Fatal("invalid fallback accepted")
		}
	}
}
