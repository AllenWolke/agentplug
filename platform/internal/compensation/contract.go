// Package compensation coordinates durable, explicitly registered business
// compensations. It is not a database snapshot restore or a Tool executor.
package compensation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const ContractVersion = "cancellation-compensation/v1"
const MaxSteps = 16384

var (
	ErrInvalid     = errors.New("invalid compensation binding")
	ErrConflict    = errors.New("compensation binding conflict")
	ErrUnavailable = errors.New("compensation authority unavailable")
	ErrPending     = errors.New("cancellation compensation incomplete")
	ErrLeaseLost   = errors.New("compensation lease lost")
	// Only an adapter with positive evidence that no inverse operation was
	// submitted may wrap this. A timeout is not such evidence.
	ErrNotSubmitted = errors.New("compensation was not submitted")
)

// Step is platform-created before the forward operation. Ref is an opaque
// reference owned by the business module, never a credential, URL or payload.
// Root binds admitted descendants to one cancellation, including successful
// children whose business effects still need compensation.
type Step struct {
	Root            sharedkernel.Scope `json:"root"`
	Scope           sharedkernel.Scope `json:"scope"`
	ID              string             `json:"step_id"`
	Kind            string             `json:"kind"`
	Tool            string             `json:"tool_name"`
	Provider        string             `json:"provider"`
	ProviderVersion string             `json:"provider_version"`
	CallID          string             `json:"call_id"`
	Fingerprint     string             `json:"fingerprint"`
	Ref             string             `json:"effect_ref"`
	DependsOn       []string           `json:"depends_on,omitempty"`
}

func token(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}

func digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}

func ScopeDigest(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal(scope)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func StepID(scope sharedkernel.Scope, kind, callID string) string {
	h := sha256.Sum256([]byte(ScopeDigest(scope) + "\x00" + kind + "\x00" + callID))
	return hex.EncodeToString(h[:])
}

func (s Step) Validate() error {
	if s.Root.ValidateTrusted() != nil || s.Scope.ValidateTrusted() != nil ||
		s.Root.TenantID != s.Scope.TenantID || s.Root.ApplicationID != s.Scope.ApplicationID ||
		(s.Scope.RunID == s.Root.RunID && s.Scope != s.Root) || (s.Scope.RunID != s.Root.RunID && s.Scope.ParentRunID == "") ||
		!token(s.Tool, 128) || !token(s.Provider, 128) || !token(s.ProviderVersion, 128) ||
		!token(s.CallID, 255) || !token(s.Ref, 255) || !digest(s.Fingerprint) ||
		s.ID != StepID(s.Scope, s.Kind, s.CallID) || len(s.DependsOn) > 32 {
		return ErrInvalid
	}
	switch s.Kind {
	case "tool", "api", "notification", "memory", "index":
	default:
		return ErrInvalid
	}
	seen := make(map[string]bool, len(s.DependsOn))
	for _, id := range s.DependsOn {
		if !digest(id) || id == s.ID || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	raw, _ := json.Marshal(s)
	if len(raw) > 16384 {
		return ErrInvalid
	}
	return nil
}

func (s Step) canonical() Step {
	s.DependsOn = append([]string(nil), s.DependsOn...)
	sort.Strings(s.DependsOn)
	return s
}

func (s Step) Digest() string {
	raw, _ := json.Marshal(s.canonical())
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (s Step) CompensationKey() string {
	h := sha256.Sum256([]byte(ContractVersion + "\x00" + s.Digest()))
	return hex.EncodeToString(h[:])
}

type StopProof struct {
	Version        string `json:"version"`
	ScopeDigest    string `json:"scope_digest"`
	Revision       uint64 `json:"revision"`
	EvidenceDigest string `json:"evidence_digest"`
}

func (p StopProof) Validate(scope sharedkernel.Scope) error {
	if p.Version != "cancellation-tree-stop/v1" || p.ScopeDigest != ScopeDigest(scope) || p.Revision == 0 || !digest(p.EvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

// Receipts are returned only by operator-installed adapters, after reading
// authoritative business/notification records. HTTP 2xx alone is insufficient.
type Receipt struct {
	Version        string `json:"version"`
	StepDigest     string `json:"step_digest"`
	Key            string `json:"compensation_key"`
	Action         string `json:"action"`
	EvidenceDigest string `json:"evidence_digest"`
}

func (r Receipt) Validate(s Step) error {
	if r.Version != ContractVersion || r.StepDigest != s.Digest() || r.Key != s.CompensationKey() || !digest(r.EvidenceDigest) {
		return ErrInvalid
	}
	switch r.Action {
	case "rolled_back", "withdrawn", "corrected", "no_effect":
		return nil
	}
	return ErrInvalid
}

type Lease struct {
	Step Step
	// ControlScope identifies this cancellation transaction. The immutable
	// effect keeps its original Root/key when a parent also enrolls it.
	ControlScope sharedkernel.Scope
	Owner        string
	Token        string
	Fence        uint64
	Until        time.Time
	Attempts     int
	Invocations  int
	Submitted    bool
}

func (l Lease) CancellationScope() sharedkernel.Scope {
	if l.ControlScope == (sharedkernel.Scope{}) {
		return l.Step.Root
	}
	return l.ControlScope
}

// OriginalEffect is an authoritative observation, not an HTTP response code.
// "unknown" never permits execution of an inverse operation. "no_effect"
// additionally proves late forward writes have been fenced by the provider.
type OriginalEffect struct {
	StepDigest     string
	State          string
	EvidenceDigest string
}

func (o OriginalEffect) Validate(s Step) error {
	if o.StepDigest != s.Digest() {
		return ErrInvalid
	}
	if o.State == "unknown" {
		return nil
	}
	if (o.State != "applied" && o.State != "no_effect") || !digest(o.EvidenceDigest) {
		return ErrInvalid
	}
	return nil
}

// Progress exposes bounded metadata only; leases, effect references and
// business snapshots never appear in the public cancellation projection.
type Progress struct {
	Version        string `json:"version"`
	CancellationID string `json:"cancellation_id"`
	Phase          string `json:"phase"`
	StopConfirmed  bool   `json:"stop_confirmed"`
	Total          int    `json:"total"`
	Compensated    int    `json:"compensated"`
	NoEffect       int    `json:"no_effect"`
	Unresolved     int    `json:"unresolved"`
	Attention      int    `json:"needs_attention"`
}
