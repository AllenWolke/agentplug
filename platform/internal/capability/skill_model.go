package capability

import (
	"context"
	"encoding/hex"
	"net/http"
	"sort"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// SkillModelBinding is orchestration metadata, never a provider parameter.
// The model ledger binds it along with the exact input; the registry requires
// an existing Run pin, so generation cannot create or change a selection.
type SkillModelBinding struct {
	VersionID string `json:"version_id"`
	Digest    string `json:"digest"`
}
type skillModelBindingsKey struct{}

func validSkillModelBindings(bindings map[string]SkillModelBinding) bool {
	if len(bindings) > 4 {
		return false
	}
	for id, binding := range bindings {
		digest, err := hex.DecodeString(binding.Digest)
		if !skillIdentifier(id) || !skillIdentifier(binding.VersionID) || err != nil || len(digest) != 32 || binding.Digest != hex.EncodeToString(digest) {
			return false
		}
	}
	return true
}

// ValidateModelBindings rechecks current authorization, approved status and
// required capabilities without disclosing instructions or making a new pin.
func (r *SkillRegistry) ValidateModelBindings(ctx context.Context, scope sharedkernel.Scope, bindings map[string]SkillModelBinding) error {
	if scope.ValidateTrusted() != nil || !validSkillModelBindings(bindings) {
		return ErrSkillDenied
	}
	ids := make([]string, 0, len(bindings))
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return r.store.Transact(ctx, scope, func(tx SkillTransaction) error {
		for _, id := range ids {
			binding := bindings[id]
			if err := tx.Authorize(ctx, "skill.discover", scope, id, ""); err != nil {
				return skillDenyUnlessAdmissionWait(err)
			}
			if err := tx.Authorize(ctx, "skill.load", scope, id, binding.VersionID); err != nil {
				return skillDenyUnlessAdmissionWait(err)
			}
			pin, found, err := tx.Pin(scope, id)
			if err != nil {
				return err
			}
			if !found || pin.VersionID != binding.VersionID || pin.Digest != binding.Digest {
				return ErrSkillConflict
			}
			version, found, err := tx.Version(id, binding.VersionID)
			if err != nil {
				return err
			}
			if !found || version.Status != "approved" {
				return ErrSkillDenied
			}
			_, digest, err := freezeSkillBundle(version.Bundle)
			if err != nil || version.Digest != binding.Digest || digest != binding.Digest {
				return ErrSkillConflict
			}
			for _, tool := range version.Bundle.RequiredTools {
				if err := tx.Authorize(ctx, "skill.require_tool", scope, id, tool); err != nil {
					return skillDenyUnlessAdmissionWait(err)
				}
			}
			for _, knowledge := range version.Bundle.RequiredKnowledge {
				if err := tx.Authorize(ctx, "skill.require_knowledge", scope, id, knowledge); err != nil {
					return skillDenyUnlessAdmissionWait(err)
				}
			}
			if err := tx.Audit("skill.model_dependency_checked", scope, id, binding.VersionID, binding.Digest); err != nil {
				return err
			}
		}
		return nil
	})
}

func (m *Module) checkModelSkillBindings(r *http.Request, op envelope) error {
	defer capabilityPhase(r.Context(), "authority.skills")()
	bindings, _ := r.Context().Value(skillModelBindingsKey{}).(map[string]SkillModelBinding)
	if len(bindings) == 0 {
		return nil
	}
	if m.skills == nil || !validSkillModelBindings(bindings) {
		return ErrSkillDenied
	}
	for id := range bindings {
		allowed := false
		for _, published := range op.Policy.Runtime.AllowedSkills {
			if published == id {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrSkillDenied
		}
	}
	// Strip this private dependency context from the nested authority callback;
	// IAM rechecks must not recursively open the same Skill SQL transaction.
	base := r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, nil))
	ctx, err := m.skillExecutionContext(base, op)
	if err != nil {
		return err
	}
	return m.skills.ValidateModelBindings(ctx, scopeFromHarness(op.Context), bindings)
}
