package policyasset

import (
	"encoding/json"
	"slices"

	"github.com/lexagent/platform/internal/jsonvaluecache"
)

// Cache immutable JSON decoding only. Resolve still reads the current scoped
// SQL row and validates the complete snapshot on every call; Effective(now),
// current source ACLs and published bindings are never cached as decisions.
var knowledgePolicyDecode = jsonvaluecache.New(128, 8<<20, parseKnowledgePolicy, cloneKnowledgePolicy)

func parseKnowledgePolicy(raw []byte) (KnowledgePolicy, error) {
	var value KnowledgePolicy
	err := json.Unmarshal(raw, &value)
	return value, err
}

func cloneKnowledgePolicy(value KnowledgePolicy) KnowledgePolicy {
	value.AllowedScopes = slices.Clone(value.AllowedScopes)
	value.DocumentBindings = slices.Clone(value.DocumentBindings)
	for i := range value.DocumentBindings {
		binding := &value.DocumentBindings[i]
		if binding.ValidFrom != nil {
			value := *binding.ValidFrom
			binding.ValidFrom = &value
		}
		if binding.ValidUntil != nil {
			value := *binding.ValidUntil
			binding.ValidUntil = &value
		}
	}
	return value
}
