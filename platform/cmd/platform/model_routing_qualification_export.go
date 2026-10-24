package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/policyasset"
)

type routingQualificationExportAssets interface {
	GetAsset(context.Context, policyasset.Scope, policyasset.AssetType, string, uint64) (policyasset.Asset, error)
}

func routingQualificationScope(scope policyasset.Scope, p policyasset.ModelPolicy) evaluationproduct.Scope {
	if p.Routing != nil && p.Routing.QualificationReuse != nil && p.Routing.QualificationReuse.Source != nil {
		scope = p.Routing.QualificationReuse.Source.Scope
	}
	return evaluationproduct.Scope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
}

// This immutable source grant licenses only publication of derived eligibility
// facts for one approved destination artifact/profile. It is not a live source
// data grant: runtime IAM and destination evidence checks remain independent.
func (v modelRoutingPublicationValidator) verifyQualificationExport(ctx context.Context, destination policyasset.Scope, p policyasset.ModelPolicy, source, current policyasset.Snapshot) error {
	invalid := policyasset.ErrInvalidAsset
	r := p.Routing.QualificationReuse
	if r == nil || r.Source == nil || r.Source.Validate() != nil {
		return invalid
	}
	ref := r.Source
	if policyasset.RoutingQualificationProfileSHA256(source) != ref.QualificationProfileSHA256 ||
		policyasset.RoutingQualificationProfileSHA256(current) != ref.QualificationProfileSHA256 {
		return invalid
	}
	store, ok := v.reusePolicies.(routingQualificationExportAssets)
	if !ok {
		return invalid
	}
	asset, err := store.GetAsset(ctx, ref.Scope, policyasset.AssetModel, ref.ModelAsset.ID, ref.ModelAsset.Revision)
	if err != nil || asset.Scope != ref.Scope || asset.Type != policyasset.AssetModel ||
		asset.ID != ref.ModelAsset.ID || asset.Revision != ref.ModelAsset.Revision ||
		asset.Status != policyasset.AssetPublished || asset.Hash != ref.ContentSHA256 || asset.CreatedBy == "" {
		return invalid
	}
	digest := sha256.Sum256(asset.Content)
	if hex.EncodeToString(digest[:]) != ref.ContentSHA256 {
		return invalid
	}
	var exported policyasset.ModelPolicy
	if json.Unmarshal(asset.Content, &exported) != nil || exported.ValidateRouting() != nil || exported.Routing == nil ||
		exported.Routing.QualificationReuse != nil || exported.Routing.ExecutionContextSHA256 != r.SourceExecutionContextSHA256 {
		return invalid
	}
	// Reconstruct the source's full context, not the destination or a rewritten
	// copy of its Runs. A different source model policy cannot widen this grant.
	granted := source
	granted.Model = exported
	if policyasset.RoutingExecutionContextSHA256(granted) != r.SourceExecutionContextSHA256 ||
		policyasset.RoutingQualificationProfileSHA256(granted) != ref.QualificationProfileSHA256 {
		return invalid
	}
	allowed := false
	for _, grant := range exported.Routing.QualificationExports {
		if grant.TargetScope == destination && grant.TargetArtifactDigest == r.TargetArtifactDigest &&
			grant.QualificationProfileSHA256 == ref.QualificationProfileSHA256 && grant.EvidenceMaxAgeSeconds() == ref.EvidenceMaxAgeSeconds() {
			allowed = true
		}
	}
	if !allowed {
		return invalid
	}
	for _, candidate := range p.Routing.Candidates {
		permitted := false
		for _, original := range exported.Routing.Candidates {
			sourceMode, sourceEffort := original.EffectiveReasoning(exported)
			targetMode, targetEffort := candidate.EffectiveReasoning(p)
			if original.ModelVersionID == candidate.ModelVersionID && original.CapabilitySHA256 == candidate.CapabilitySHA256 &&
				original.QualityEvidenceID == candidate.QualityEvidenceID && original.QualityEvidenceSHA256 == candidate.QualityEvidenceSHA256 &&
				sourceMode == targetMode && sourceEffort == targetEffort &&
				policyasset.ModelComplexityRank(original.MaxComplexity) >= policyasset.ModelComplexityRank(candidate.MaxComplexity) {
				permitted = true
			}
		}
		if !permitted {
			return invalid
		}
	}
	return nil
}

func (v modelRoutingPublicationValidator) validateQualificationExports(ctx context.Context, scope policyasset.Scope, p policyasset.ModelPolicy) error {
	if len(p.Routing.QualificationExports) == 0 {
		return nil
	}
	if p.Routing.QualificationReuse != nil || v.reusePolicies == nil || v.reuseCatalog == nil {
		return policyasset.ErrInvalidAsset
	}
	source, err := v.reusePolicies.GetSnapshot(ctx, scope)
	if err != nil {
		return policyasset.ErrInvalidAsset
	}
	source.Model = p
	if policyasset.RoutingExecutionContextSHA256(source) != p.Routing.ExecutionContextSHA256 {
		return policyasset.ErrInvalidAsset
	}
	profile := policyasset.RoutingQualificationProfileSHA256(source)
	for _, grant := range p.Routing.QualificationExports {
		version, err := v.reuseCatalog.GetVersion(ctx, grant.TargetScope.AgentVersionID)
		if grant.Validate() != nil || grant.TargetScope.AgentID != scope.AgentID || profile == "" ||
			grant.QualificationProfileSHA256 != profile || err != nil || version.ID != grant.TargetScope.AgentVersionID ||
			version.Status != catalog.DefinitionPublished || version.ApprovedBy == "" || version.ArtifactDigest != grant.TargetArtifactDigest {
			return policyasset.ErrInvalidAsset
		}
	}
	return nil
}
