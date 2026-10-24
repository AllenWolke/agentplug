package capability

func (r ModelRouteRequest) allowsContextCacheMode(mode string) bool {
	return r.ContextCacheMode == "" || mode == r.ContextCacheMode ||
		mode == "" && r.ContextCacheMode == "provider_prefix" && r.AllowUnreportedPrefixPreparation
}
