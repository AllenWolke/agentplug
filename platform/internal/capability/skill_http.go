package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type skillRuntimeContext struct {
	Scope  sharedkernel.Scope
	Lease  sharedkernel.ExecutionLeaseBinding
	Policy policyasset.Snapshot
	Check  func(context.Context) error
}
type skillRuntimeContextKey struct{}

// SkillRuntimeAuthority is a composition Port, available only after the signed
// gateway authenticated the execution and installed this private context.
func SkillRuntimeAuthority(ctx context.Context, scope sharedkernel.Scope) (sharedkernel.ExecutionLeaseBinding, policyasset.Snapshot, error) {
	b, ok := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
	if !ok || b.Scope != scope || b.Check == nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, ErrSkillDenied
	}
	if err := b.Check(ctx); err != nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, skillDenyUnlessAdmissionWait(err)
	}
	return b.Lease, b.Policy, nil
}

// skillDenyUnlessAdmissionWait keeps a row-lock wait visible to model-budget
// admission. Finished skill denials stay the stable sentinel.
func skillDenyUnlessAdmissionWait(err error) error {
	if err == nil || budgetAdmissionDeferred(err) {
		return err
	}
	return ErrSkillDenied
}

func (m *Module) SetSkillRegistry(registry *SkillRegistry) { m.skills = registry }

// Only disclosure is on the Agent listener. Register/review/publish/revoke
// must use the separate authenticated human control plane, never this route.
func (m *Module) loadSkill(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	if m.skills == nil {
		m.error(w, 503, "SKILL_UNAVAILABLE", "public skill registry is not configured", op.Context.TraceID)
		return
	}
	var input struct {
		SkillID string `json:"skill_id"`
		Section string `json:"section"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !skillIdentifier(input.SkillID) || (input.Section != "" && !skillIdentifier(input.Section)) {
		m.error(w, 400, "INVALID_REQUEST", "valid skill and optional section required", op.Context.TraceID)
		return
	}
	allowed := false
	for _, id := range op.Policy.Runtime.AllowedSkills {
		if id == input.SkillID {
			allowed = true
		}
	}
	if !allowed {
		m.error(w, 403, "SKILL_DENIED", "skill not allowed by published runtime policy", op.Context.TraceID)
		return
	}
	ctx, err := m.skillExecutionContext(r, op)
	if err != nil {
		m.error(w, 403, "SKILL_DENIED", "trusted execution lease required", op.Context.TraceID)
		return
	}
	result, err := m.skills.Load(ctx, scopeFromHarness(op.Context), input.SkillID, input.Section)
	if err != nil {
		switch {
		case errors.Is(err, ErrSkillDenied):
			m.error(w, 403, "SKILL_DENIED", "skill disclosure denied", op.Context.TraceID)
		case errors.Is(err, ErrSkillConflict):
			m.error(w, 409, "SKILL_CONFLICT", "skill version or pin conflict", op.Context.TraceID)
		default:
			m.error(w, 503, "SKILL_UNAVAILABLE", "skill disclosure unavailable", op.Context.TraceID)
		}
		return
	}
	m.currentResult(w, r, op, map[string]any{"skill": result})
}

// Used only after gateway authorization has verified the signed context.
func (m *Module) skillExecutionContext(r *http.Request, op envelope) (context.Context, error) {
	parts := strings.Split(op.Context.PlatformContextToken, ".")
	var claims struct {
		Revision  uint64 `json:"execution_revision"`
		TokenHash string `json:"lease_token_hash"`
	}
	if len(parts) != 3 {
		return nil, ErrSkillDenied
	}
	body, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if decodeErr != nil || json.Unmarshal(body, &claims) != nil || claims.Revision == 0 || len(claims.TokenHash) != 64 {
		return nil, ErrSkillDenied
	}
	scope := scopeFromHarness(op.Context)
	lease := sharedkernel.ExecutionLeaseBinding{Revision: claims.Revision, TokenHash: claims.TokenHash}
	ctx := sharedkernel.WithExecutionLease(r.Context(), lease)
	ctx = context.WithValue(ctx, skillRuntimeContextKey{}, skillRuntimeContext{Scope: scope, Lease: lease, Policy: op.Policy, Check: func(ctx context.Context) error { return m.checkCurrentCapability(r.WithContext(ctx), op) }})
	return ctx, nil
}
