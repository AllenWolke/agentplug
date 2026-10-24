package policyasset

// A qualification export permits a specific destination to publish a derived
// model policy. It grants no caller access to source Runs or business content.
// Existing policies export nothing unless the source owner explicitly opts in.
type ModelRouteQualificationExport struct {
	TargetScope                Scope  `json:"target_scope"`
	TargetArtifactDigest       string `json:"target_artifact_digest"`
	QualificationProfileSHA256 string `json:"qualification_profile_sha256"`
	MaxEvidenceAgeSeconds      int64  `json:"max_evidence_age_seconds,omitempty"`
}

type ModelRouteQualificationSource struct {
	Scope                      Scope    `json:"scope"`
	ModelAsset                 AssetRef `json:"model_asset"`
	ContentSHA256              string   `json:"content_sha256"`
	QualificationProfileSHA256 string   `json:"qualification_profile_sha256"`
	MaxEvidenceAgeSeconds      int64    `json:"max_evidence_age_seconds,omitempty"`
}

func finiteRoutingScope(s Scope) bool {
	return s.validate() == nil && routingID(s.TenantID) && routingID(s.DepartmentID) &&
		routingID(s.ApplicationID) && routingID(s.AgentID) && routingID(s.AgentVersionID)
}

func (e ModelRouteQualificationExport) Validate() error {
	if !finiteRoutingScope(e.TargetScope) || !routingArtifactDigest(e.TargetArtifactDigest) || !routingSHA(e.QualificationProfileSHA256) || !qualificationAgeValid(e.MaxEvidenceAgeSeconds) {
		return ErrMissingPolicy
	}
	return nil
}

func (s ModelRouteQualificationSource) Validate() error {
	if !finiteRoutingScope(s.Scope) || !routingID(s.ModelAsset.ID) || s.ModelAsset.Revision < 2 ||
		s.ModelAsset.Revision > 1_000_000 || !routingSHA(s.ContentSHA256) || !routingSHA(s.QualificationProfileSHA256) || !qualificationAgeValid(s.MaxEvidenceAgeSeconds) {
		return ErrMissingPolicy
	}
	return nil
}

// The existing release gate remains 24h. An independently approved, finite
// source export may explicitly retain an immutable measurement for up to 7d
// at publication. The original ProducedAt and all quality checks remain exact.
func qualificationAgeValid(seconds int64) bool {
	return seconds == 0 || seconds >= 86400 && seconds <= 7*86400
}

func effectiveQualificationAge(seconds int64) int64 {
	if seconds == 0 {
		return 86400
	}
	return seconds
}

func (e ModelRouteQualificationExport) EvidenceMaxAgeSeconds() int64 {
	return effectiveQualificationAge(e.MaxEvidenceAgeSeconds)
}

func (s ModelRouteQualificationSource) EvidenceMaxAgeSeconds() int64 {
	return effectiveQualificationAge(s.MaxEvidenceAgeSeconds)
}

func (p ModelRoutingPolicy) QualificationEvidenceMaxAgeSeconds() int64 {
	if p.QualificationReuse != nil && p.QualificationReuse.Source != nil {
		return p.QualificationReuse.Source.EvidenceMaxAgeSeconds()
	}
	if len(p.QualificationExports) == 0 {
		return 86400
	}
	// One shared source pool must qualify under every destination grant.
	maximum := int64(7 * 86400)
	for _, grant := range p.QualificationExports {
		if age := grant.EvidenceMaxAgeSeconds(); age < maximum {
			maximum = age
		}
	}
	return maximum
}

func routingArtifactDigest(value string) bool {
	return len(value) == len("sha256:")+64 && value[:len("sha256:")] == "sha256:" && routingSHA(value[len("sha256:"):])
}
