package capability

import (
	"context"
	"encoding/json"
	"net/http"
)

type knowledgeSkillSelection struct {
	SkillID  string   `json:"skill_id"`
	Sections []string `json:"sections"`
}

// Instructions are loaded from the approved registry, never accepted as raw
// Agent-supplied content. Every version must match this Run's existing pin.
func (m *Module) knowledgeSkillContext(r *http.Request, op envelope, bindings map[string]SkillModelBinding, selections []knowledgeSkillSelection) (string, error) {
	if len(bindings) == 0 && len(selections) == 0 {
		return "", nil
	}
	if m.skills == nil || !validSkillModelBindings(bindings) || len(selections) != len(bindings) || len(selections) > 4 {
		return "", ErrSkillDenied
	}
	base := r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, nil))
	ctx, err := m.skillExecutionContext(base, op)
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	disclosures := []SkillDisclosure{}
	for _, selection := range selections {
		binding, exists := bindings[selection.SkillID]
		if !exists || seen[selection.SkillID] || !skillIdentifier(selection.SkillID) || len(selection.Sections) > 4 {
			return "", ErrSkillDenied
		}
		seen[selection.SkillID] = true
		sections := map[string]bool{}
		for _, section := range append([]string{""}, selection.Sections...) {
			if section != "" && (!skillIdentifier(section) || sections[section]) {
				return "", ErrSkillDenied
			}
			if section == "" && sections[section] {
				return "", ErrSkillDenied
			}
			sections[section] = true
			disclosure, err := m.skills.Load(ctx, scopeFromHarness(op.Context), selection.SkillID, section)
			if err != nil {
				return "", err
			}
			if disclosure.VersionID != binding.VersionID || disclosure.Digest != binding.Digest {
				return "", ErrSkillConflict
			}
			disclosures = append(disclosures, disclosure)
		}
	}
	encoded, err := json.Marshal(map[string]any{"type": "skill_instructions", "instruction_trust": "untrusted_data", "skills": disclosures})
	if err != nil || len(encoded) > 16<<10 {
		return "", ErrSkillDenied
	}
	return string(encoded), nil
}
