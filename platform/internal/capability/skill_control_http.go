package capability

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type SkillControlPlane struct {
	Registry *SkillRegistry
	Resolve  func(*http.Request, *SkillManagementNamespace) (sharedkernel.Scope, error)
}

type SkillManagementNamespace struct {
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
}

func (m *Module) SetSkillControlPlane(control *SkillControlPlane) { m.skillControl = control }
func (m *Module) skillControlHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	if m.internalToken == "" || !hmac.Equal([]byte(r.Header.Get("X-Internal-Token")), []byte(m.internalToken)) || r.Header.Get("X-Browser-Module") != "1" || r.Header.Get("X-Principal-Type") != "user" {
		m.error(w, 403, "TRUSTED_USER_CONTEXT_REQUIRED", "authenticated human gateway required", "")
		return
	}
	control := m.skillControl
	if control == nil || control.Registry == nil || control.Resolve == nil {
		m.error(w, 503, "SKILL_UNAVAILABLE", "skill management unavailable", "")
		return
	}
	var input struct {
		Namespace        *SkillManagementNamespace `json:"namespace,omitempty"`
		Bundle           *SkillBundle              `json:"bundle,omitempty"`
		SkillID          string                    `json:"skill_id,omitempty"`
		VersionID        string                    `json:"version_id,omitempty"`
		Digest           string                    `json:"digest,omitempty"`
		ExpectedRevision uint64                    `json:"expected_revision,omitempty"`
		Decision         string                    `json:"decision,omitempty"`
		Release          *SkillRelease             `json:"release,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 96<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		m.error(w, 400, "INVALID_REQUEST", "invalid skill management input", "")
		return
	}
	actor, err := control.Resolve(r, input.Namespace)
	if err != nil || actor.Validate() != nil || actor.PrincipalType != "user" {
		m.error(w, 403, "SKILL_DENIED", "current human session and valid namespace required", "")
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/skills/")
	var result any
	switch action {
	case "inspect":
		if input.Bundle != nil || input.Release != nil || input.Digest != "" || input.Decision != "" || input.ExpectedRevision != 0 {
			m.error(w, 400, "INVALID_REQUEST", "skill and optional version required", actor.TraceID)
			return
		}
		result, err = control.Registry.Inspect(r.Context(), actor, input.SkillID, input.VersionID)
	case "register":
		if input.Bundle == nil || input.SkillID != "" || input.VersionID != "" || input.Release != nil || input.Decision != "" || input.Digest != "" || input.ExpectedRevision != 0 {
			m.error(w, 400, "INVALID_REQUEST", "only a skill bundle is accepted", actor.TraceID)
			return
		}
		result, err = control.Registry.Register(r.Context(), actor, *input.Bundle)
	case "review":
		if input.Bundle != nil || input.Release != nil {
			m.error(w, 400, "INVALID_REQUEST", "review requires exact version and digest", actor.TraceID)
			return
		}
		err = control.Registry.Review(r.Context(), actor, input.SkillID, input.VersionID, input.Digest, input.ExpectedRevision, input.Decision)
		result = map[string]any{"skill_id": input.SkillID, "version_id": input.VersionID, "decision": input.Decision}
	case "publish":
		if input.Release == nil || input.Bundle != nil || input.VersionID != "" || input.Digest != "" || input.Decision != "" || input.Release.Revision != 0 {
			m.error(w, 400, "INVALID_REQUEST", "release and expected revision required", actor.TraceID)
			return
		}
		err = control.Registry.Publish(r.Context(), actor, input.SkillID, input.ExpectedRevision, *input.Release)
		result = map[string]any{"skill_id": input.SkillID, "revision": input.ExpectedRevision + 1}
	default:
		m.error(w, 404, "NOT_FOUND", "unknown skill management operation", actor.TraceID)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrSkillDenied):
			m.error(w, 403, "SKILL_DENIED", "skill management denied", actor.TraceID)
		case errors.Is(err, ErrSkillConflict):
			m.error(w, 409, "SKILL_CONFLICT", "immutable version or revision conflict", actor.TraceID)
		default:
			m.error(w, 503, "SKILL_UNAVAILABLE", "skill transaction unavailable", actor.TraceID)
		}
		return
	}
	// Store authorizer rechecks the browser session before transaction commit.
	if _, err = control.Resolve(r, input.Namespace); err != nil {
		m.error(w, 403, "SKILL_DENIED", "current human session required", actor.TraceID)
		return
	}
	m.write(w, 200, response{Code: 0, Data: result, TraceID: actor.TraceID})
}
