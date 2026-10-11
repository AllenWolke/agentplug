package capability

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrSkillDenied = errors.New("skill operation denied")
var ErrSkillConflict = errors.New("skill revision or immutable content conflict")
var ErrSkillUnavailable = errors.New("skill registry unavailable")

// SkillBundle contains instructions, never executable authority or credentials.
// Tools and knowledge listed here are requirements, not grants.
type SkillBundle struct {
	Protocol          string            `json:"protocol"`
	SkillID           string            `json:"skill_id"`
	VersionID         string            `json:"version_id"`
	Title             string            `json:"title"`
	Summary           string            `json:"summary"`
	Sections          map[string]string `json:"sections"`
	RequiredTools     []string          `json:"required_tools"`
	RequiredKnowledge []string          `json:"required_knowledge"`
}
type SkillVersion struct {
	Bundle     SkillBundle `json:"bundle"`
	Digest     string      `json:"digest"`
	AuthorID   string      `json:"author_id"`
	ReviewerID string      `json:"reviewer_id"`
	Status     string      `json:"status"`
	Revision   uint64      `json:"revision"`
	CreatedAt  time.Time   `json:"created_at"`
}
type SkillRelease struct {
	StableVersion        string `json:"stable_version"`
	CandidateVersion     string `json:"candidate_version"`
	CandidateBasisPoints int    `json:"candidate_basis_points"`
	Revision             uint64 `json:"revision"`
}
type SkillPin struct {
	VersionID       string `json:"version_id"`
	Digest          string `json:"digest"`
	ReleaseRevision uint64 `json:"release_revision"`
}
type SkillDisclosure struct {
	Version          string   `json:"version"`
	SkillID          string   `json:"skill_id"`
	VersionID        string   `json:"version_id"`
	Digest           string   `json:"digest"`
	ReleaseRevision  uint64   `json:"release_revision"`
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	SectionNames     []string `json:"section_names"`
	Section          string   `json:"section,omitempty"`
	Content          string   `json:"content,omitempty"`
	InstructionTrust string   `json:"instruction_trust"`
}

// Every Store transaction must lock current version/release rows, atomically
// persist changes and metadata Audit+Outbox, and roll back on any callback error.
// Versions are INSERT-only for content; lifecycle mutations cannot edit Bundle.
type SkillTransaction interface {
	Authorize(context.Context, string, sharedkernel.Scope, string, string) error
	Version(string, string) (SkillVersion, bool, error)
	InsertVersion(SkillVersion) error
	ReviewVersion(string, string, uint64, string, string) error
	Release(string) (SkillRelease, bool, error)
	WriteRelease(string, uint64, SkillRelease) error
	Pin(sharedkernel.Scope, string) (SkillPin, bool, error)
	InsertPin(sharedkernel.Scope, string, SkillPin) error
	Audit(string, sharedkernel.Scope, string, string, string) error
}
type SkillStore interface {
	Transact(context.Context, sharedkernel.Scope, func(SkillTransaction) error) error
}
type SkillRegistry struct{ store SkillStore }

func NewSkillRegistry(store SkillStore) (*SkillRegistry, error) {
	if store == nil {
		return nil, ErrSkillUnavailable
	}
	return &SkillRegistry{store: store}, nil
}

func skillIdentifier(s string) bool {
	return s != "" && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "*\x00\r\n")
}

// Inspect is a human management read, not a business invocation or bypass of
// runtime disclosure. It provides the exact digest/revision for review and CAS.
func (r *SkillRegistry) Inspect(ctx context.Context, actor sharedkernel.Scope, skill, version string) (map[string]any, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || !skillIdentifier(skill) || (version != "" && !skillIdentifier(version)) {
		return nil, ErrSkillDenied
	}
	var result map[string]any
	err := r.store.Transact(ctx, actor, func(tx SkillTransaction) error {
		if tx.Authorize(ctx, "skill.inspect", actor, skill, version) != nil {
			return ErrSkillDenied
		}
		if version != "" {
			record, found, err := tx.Version(skill, version)
			if err != nil {
				return err
			}
			if !found {
				return ErrSkillDenied
			}
			result = map[string]any{"skill_id": skill, "version": record}
			return tx.Audit("skill.version_inspected", actor, skill, version, record.Digest)
		}
		release, found, err := tx.Release(skill)
		if err != nil {
			return err
		}
		result = map[string]any{"skill_id": skill, "release": nil}
		if found {
			result["release"] = release
		}
		body, _ := json.Marshal(result)
		hash := sha256.Sum256(body)
		return tx.Audit("skill.release_inspected", actor, skill, "", hex.EncodeToString(hash[:]))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func freezeSkillBundle(bundle SkillBundle) (SkillBundle, string, error) {
	bundle.RequiredTools = append([]string(nil), bundle.RequiredTools...)
	bundle.RequiredKnowledge = append([]string(nil), bundle.RequiredKnowledge...)
	if bundle.Protocol != "skill-bundle/v1" || !skillIdentifier(bundle.SkillID) || !skillIdentifier(bundle.VersionID) || bundle.Title == "" || len(bundle.Title) > 256 || bundle.Summary == "" || len(bundle.Summary) > 2048 || len(bundle.Sections) == 0 || len(bundle.Sections) > 16 || len(bundle.RequiredTools) > 32 || len(bundle.RequiredKnowledge) > 32 {
		return SkillBundle{}, "", ErrSkillDenied
	}
	for key, text := range bundle.Sections {
		if !skillIdentifier(key) || text == "" || len(text) > 16<<10 || strings.ContainsRune(text, '\x00') {
			return SkillBundle{}, "", ErrSkillDenied
		}
	}
	for _, items := range [][]string{bundle.RequiredTools, bundle.RequiredKnowledge} {
		seen := map[string]bool{}
		for _, item := range items {
			if !skillIdentifier(item) || seen[item] {
				return SkillBundle{}, "", ErrSkillDenied
			}
			seen[item] = true
		}
		sort.Strings(items)
	}
	// Normalize before hashing and clone caller-owned maps/slices.
	raw, err := json.Marshal(bundle)
	if err != nil || len(raw) > 64<<10 {
		return SkillBundle{}, "", ErrSkillDenied
	}
	var frozen SkillBundle
	if json.Unmarshal(raw, &frozen) != nil {
		return SkillBundle{}, "", ErrSkillDenied
	}
	digest := sha256.Sum256(raw)
	return frozen, hex.EncodeToString(digest[:]), nil
}

func (r *SkillRegistry) Register(ctx context.Context, actor sharedkernel.Scope, bundle SkillBundle) (SkillVersion, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return SkillVersion{}, ErrSkillDenied
	}
	frozen, digest, err := freezeSkillBundle(bundle)
	if err != nil {
		return SkillVersion{}, err
	}
	var result SkillVersion
	err = r.store.Transact(ctx, actor, func(tx SkillTransaction) error {
		if tx.Authorize(ctx, "skill.register", actor, frozen.SkillID, frozen.VersionID) != nil {
			return ErrSkillDenied
		}
		old, found, err := tx.Version(frozen.SkillID, frozen.VersionID)
		if err != nil {
			return err
		}
		if found {
			if old.Digest != digest || old.AuthorID != actor.PrincipalID {
				return ErrSkillConflict
			}
			result = old
			return nil
		}
		result = SkillVersion{Bundle: frozen, Digest: digest, AuthorID: actor.PrincipalID, Status: "submitted", Revision: 1, CreatedAt: time.Now().UTC()}
		if tx.InsertVersion(result) != nil {
			return ErrSkillUnavailable
		}
		return tx.Audit("skill.registered", actor, frozen.SkillID, frozen.VersionID, digest)
	})
	if err != nil {
		return SkillVersion{}, err
	}
	return result, nil
}

func (r *SkillRegistry) Review(ctx context.Context, actor sharedkernel.Scope, skill, version, digest string, expected uint64, decision string) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || !skillIdentifier(skill) || !skillIdentifier(version) || expected == 0 || (decision != "approved" && decision != "rejected" && decision != "revoked") {
		return ErrSkillDenied
	}
	return r.store.Transact(ctx, actor, func(tx SkillTransaction) error {
		if tx.Authorize(ctx, "skill."+decision, actor, skill, version) != nil {
			return ErrSkillDenied
		}
		old, found, err := tx.Version(skill, version)
		if err != nil {
			return err
		}
		if !found || old.Digest != digest || old.Revision != expected {
			return ErrSkillConflict
		}
		if decision == "revoked" {
			if old.Status != "approved" && old.Status != "submitted" {
				return ErrSkillConflict
			}
		} else if old.Status != "submitted" || old.AuthorID == actor.PrincipalID {
			return ErrSkillDenied
		}
		if tx.ReviewVersion(skill, version, expected, decision, actor.PrincipalID) != nil {
			return ErrSkillConflict
		}
		return tx.Audit("skill."+decision, actor, skill, version, digest)
	})
}

// Publish also performs rollback: select an earlier approved immutable version
// with a new release revision. Revoked versions are never resurrected.
func (r *SkillRegistry) Publish(ctx context.Context, actor sharedkernel.Scope, skill string, expected uint64, release SkillRelease) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || !skillIdentifier(skill) || !skillIdentifier(release.StableVersion) || release.CandidateBasisPoints < 0 || release.CandidateBasisPoints > 10000 || release.CandidateVersion == release.StableVersion || (release.CandidateVersion == "" && release.CandidateBasisPoints != 0) || (release.CandidateVersion != "" && (!skillIdentifier(release.CandidateVersion) || release.CandidateBasisPoints == 0)) {
		return ErrSkillDenied
	}
	return r.store.Transact(ctx, actor, func(tx SkillTransaction) error {
		if tx.Authorize(ctx, "skill.publish", actor, skill, release.StableVersion) != nil {
			return ErrSkillDenied
		}
		old, found, err := tx.Release(skill)
		if err != nil {
			return err
		}
		if found && old.Revision != expected || !found && expected != 0 {
			return ErrSkillConflict
		}
		for _, version := range []string{release.StableVersion, release.CandidateVersion} {
			if version == "" {
				continue
			}
			record, ok, err := tx.Version(skill, version)
			if err != nil {
				return err
			}
			if !ok || record.Status != "approved" || record.ReviewerID == "" || record.ReviewerID == record.AuthorID {
				return ErrSkillDenied
			}
			if tx.Authorize(ctx, "skill.publish", actor, skill, version) != nil {
				return ErrSkillDenied
			}
		}
		release.Revision = expected + 1
		if release.Revision == 0 {
			return ErrSkillConflict
		}
		if tx.WriteRelease(skill, expected, release) != nil {
			return ErrSkillConflict
		}
		body, _ := json.Marshal(release)
		hash := sha256.Sum256(body)
		return tx.Audit("skill.release_changed", actor, skill, release.StableVersion, hex.EncodeToString(hash[:]))
	})
}

func skillRunKey(scope sharedkernel.Scope, skill string) string {
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentInstanceID, scope.AgentVersionID, scope.InstallationID, scope.PrincipalType, scope.PrincipalID, scope.RunID, scope.SessionID, skill})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func skillCandidate(scope sharedkernel.Scope, skill string, release SkillRelease) string {
	hash := sha256.Sum256([]byte("skill-cohort/v1\x00" + skillRunKey(scope, skill)))
	if release.CandidateVersion != "" && int(binary.BigEndian.Uint64(hash[:8])%10000) < release.CandidateBasisPoints {
		return release.CandidateVersion
	}
	return release.StableVersion
}

// Load pins a run to the first chosen immutable version. A later rollout or
// rollback affects new runs; each disclosure still requires current authority.
func (r *SkillRegistry) Load(ctx context.Context, scope sharedkernel.Scope, skill, section string) (SkillDisclosure, error) {
	if scope.ValidateTrusted() != nil || !skillIdentifier(skill) || (section != "" && !skillIdentifier(section)) {
		return SkillDisclosure{}, ErrSkillDenied
	}
	var result SkillDisclosure
	err := r.store.Transact(ctx, scope, func(tx SkillTransaction) error {
		if tx.Authorize(ctx, "skill.discover", scope, skill, "") != nil {
			return ErrSkillDenied
		}
		pin, pinned, err := tx.Pin(scope, skill)
		if err != nil {
			return err
		}
		if !pinned {
			release, found, err := tx.Release(skill)
			if err != nil {
				return err
			}
			if !found {
				return ErrSkillDenied
			}
			pin.VersionID = skillCandidate(scope, skill, release)
			pin.ReleaseRevision = release.Revision
		}
		if tx.Authorize(ctx, "skill.load", scope, skill, pin.VersionID) != nil {
			return ErrSkillDenied
		}
		version, found, err := tx.Version(skill, pin.VersionID)
		if err != nil {
			return err
		}
		if !found || version.Status != "approved" {
			return ErrSkillDenied
		}
		_, digest, err := freezeSkillBundle(version.Bundle)
		if err != nil || digest != version.Digest || pinned && pin.Digest != digest {
			return ErrSkillConflict
		}
		// The adapter must intersect these requirements with the current published
		// model/tool/knowledge policy and caller+Agent IAM. This never grants them.
		for _, tool := range version.Bundle.RequiredTools {
			if tx.Authorize(ctx, "skill.require_tool", scope, skill, tool) != nil {
				return ErrSkillDenied
			}
		}
		for _, knowledge := range version.Bundle.RequiredKnowledge {
			if tx.Authorize(ctx, "skill.require_knowledge", scope, skill, knowledge) != nil {
				return ErrSkillDenied
			}
		}
		content := ""
		if section != "" {
			var exists bool
			content, exists = version.Bundle.Sections[section]
			if !exists {
				return ErrSkillDenied
			}
		}
		if !pinned {
			pin.Digest = digest
			if tx.InsertPin(scope, skill, pin) != nil {
				return ErrSkillConflict
			}
		}
		names := make([]string, 0, len(version.Bundle.Sections))
		for name := range version.Bundle.Sections {
			names = append(names, name)
		}
		sort.Strings(names)
		result = SkillDisclosure{Version: "skill-disclosure/v1", SkillID: skill, VersionID: pin.VersionID, Digest: digest, ReleaseRevision: pin.ReleaseRevision, Title: version.Bundle.Title, Summary: version.Bundle.Summary, SectionNames: names, Section: section, Content: content, InstructionTrust: "untrusted_data"}
		return tx.Audit("skill.disclosed", scope, skill, pin.VersionID, digest)
	})
	if err != nil {
		return SkillDisclosure{}, err
	}
	return result, nil
}
