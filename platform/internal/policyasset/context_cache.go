package policyasset

// ContextCachePolicy controls prefix preparation, not response reuse. Provider
// eviction/retention remains a property of the approved inference service.
type ContextCachePolicy struct {
	Version                  string `json:"version"`
	Mode                     string `json:"mode"`
	Isolation                string `json:"isolation"`
	UnsupportedModelBehavior string `json:"unsupported_model_behavior,omitempty"`
}

func (p ModelPolicy) ValidateContextCache() error {
	if p.ContextCache == nil {
		return nil
	}
	c := p.ContextCache
	if c.Mode != "provider_prefix" || c.Isolation != "session" ||
		(c.Version != "context-prefix/v1" && c.Version != "context-prefix/v2") ||
		c.Version == "context-prefix/v1" && c.UnsupportedModelBehavior != "" ||
		c.Version == "context-prefix/v2" && c.UnsupportedModelBehavior != "prepare_prefix" {
		return ErrMissingPolicy
	}
	return nil
}

// Preparation-only fallback keeps the authenticated prefix and fingerprints
// identical even when a model does not declare native cache support. It grants
// no cache hit, token saving or price discount: missing usage stays unknown.
func (p ModelPolicy) AllowsUnreportedPrefixPreparation() bool {
	return p.ValidateContextCache() == nil && p.ContextCache != nil &&
		p.ContextCache.Version == "context-prefix/v2" && p.ContextCache.UnsupportedModelBehavior == "prepare_prefix"
}

func (p ModelPolicy) AllowsContextCacheMode(mode string) bool {
	if p.ValidateContextCache() != nil {
		return false
	}
	return p.ContextCache == nil || mode == p.ContextCache.Mode || mode == "" && p.AllowsUnreportedPrefixPreparation()
}
