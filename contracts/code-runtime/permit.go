// Package coderuntime defines the shared controller protocol, not a client
// permission authority. Only the platform signs permits after current IAM.
package coderuntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const domain = "agentplug/code-permit/v1\x00"
const MaxTokenBytes = 256 << 10

var ErrPermit = errors.New("code execution permit denied")

type Limits struct {
	MemoryBytes    int64 `json:"memory_bytes"`
	CPUMilli       int   `json:"cpu_milli"`
	CPUSeconds     int   `json:"cpu_seconds"`
	PIDs           int   `json:"pids"`
	DiskBytes      int64 `json:"disk_bytes"`
	TimeoutSeconds int   `json:"timeout_seconds"`
	OutputBytes    int   `json:"output_bytes"`
}

func (l Limits) Validate() error {
	if l.MemoryBytes < 64<<20 || l.MemoryBytes > 512<<20 || l.CPUMilli < 100 || l.CPUMilli > 1000 || l.CPUSeconds < 1 || l.CPUSeconds > 30 || l.PIDs < 8 || l.PIDs > 64 || l.DiskBytes < 4<<20 || l.DiskBytes > 64<<20 || l.TimeoutSeconds < 10 || l.TimeoutSeconds > 60 || l.OutputBytes < 64<<10 || l.OutputBytes > 1<<20 {
		return ErrPermit
	}
	return nil
}

type Permit struct {
	Version            string `json:"version"`
	Action             string `json:"action"`
	ControllerID       string `json:"controller_id"`
	ScopeHash          string `json:"scope_hash"`
	TenantID           string `json:"tenant_id"`
	DepartmentID       string `json:"department_id"`
	ApplicationID      string `json:"application_id"`
	CallerID           string `json:"caller_id"`
	CallerType         string `json:"caller_type"`
	AgentID            string `json:"agent_id"`
	AgentVersionID     string `json:"agent_version_id"`
	AgentInstanceID    string `json:"agent_instance_id"`
	InstallationID     string `json:"installation_id"`
	RunID              string `json:"run_id"`
	SessionID          string `json:"session_id"`
	TraceID            string `json:"trace_id"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	PolicyHash         string `json:"policy_hash"`
	ApprovalID         string `json:"approval_id"`
	ToolName           string `json:"tool_name"`
	CallID             string `json:"call_id"`
	Fingerprint        string `json:"fingerprint"`
	LeaseFence         uint64 `json:"lease_fence"`
	ProfileID          string `json:"profile_id"`
	Language           string `json:"language"`
	Code               string `json:"code"`
	Limits             Limits `json:"limits"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"`
}

func (p Permit) Validate(now time.Time) error {
	for _, value := range []string{p.ControllerID, p.TenantID, p.DepartmentID, p.ApplicationID, p.CallerID, p.AgentID, p.AgentVersionID, p.AgentInstanceID, p.InstallationID, p.RunID, p.SessionID, p.TraceID, p.ToolName, p.CallID, p.ProfileID, p.ApprovalID} {
		if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return ErrPermit
		}
	}
	if p.Version != "code-permit/v1" || (p.Action != "execute" && p.Action != "receipt") || (p.CallerType != "user" && p.CallerType != "service_principal") || p.AuthorizationEpoch == 0 || len(p.PolicyHash) != 64 || len(p.Fingerprint) != 64 || !strings.HasPrefix(p.ToolName, "code.") || p.Language != "python" && p.Language != "javascript" && p.Language != "shell" || len(p.Code) > 64<<10 || strings.ContainsRune(p.Code, '\x00') || p.Limits.Validate() != nil || p.Action == "execute" && (p.LeaseFence == 0 || p.Code == "") || p.Action == "receipt" && p.Code != "" || p.IssuedAt <= 0 || p.IssuedAt > now.Unix()+5 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 60 || now.Unix() >= p.ExpiresAt {
		return ErrPermit
	}
	wantScope := ScopeHash(p)
	wantFingerprint, err := Fingerprint(p.ToolName, p.Code)
	if err != nil || wantScope != p.ScopeHash || p.Action == "execute" && wantFingerprint != p.Fingerprint {
		return ErrPermit
	}
	return nil
}
func ScopeHash(p Permit) string {
	body, _ := json.Marshal([]string{p.TenantID, p.DepartmentID, p.ApplicationID, p.AgentID, p.AgentInstanceID, p.CallerType, p.CallerID, p.InstallationID, p.AgentVersionID, p.SessionID, p.RunID})
	return fmt.Sprintf("%x", sha256.Sum256(body))
}
func Fingerprint(name, code string) (string, error) {
	body, err := json.Marshal(struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
	}{name, map[string]any{"code": code}})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(body)), nil
}
func OperationKey(p Permit) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(p.ScopeHash+"\x00"+p.CallID)))
}

type Signer struct{ key ed25519.PrivateKey }

func NewSigner(private ed25519.PrivateKey) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return nil, ErrPermit
	}
	return &Signer{key: append(ed25519.PrivateKey(nil), private...)}, nil
}
func (s *Signer) String() string   { return "code-permit-signer[redacted]" }
func (s *Signer) GoString() string { return s.String() }
func (s *Signer) Sign(p Permit, now time.Time) (string, error) {
	if s == nil || p.Validate(now) != nil {
		return "", ErrPermit
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", ErrPermit
	}
	token := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, append([]byte(domain), body...)))
	if len(token) > MaxTokenBytes {
		return "", ErrPermit
	}
	return token, nil
}
func Verify(token string, public ed25519.PublicKey, controller, action string, now time.Time) (p Permit, err error) {
	if len(public) != ed25519.PublicKeySize || len(token) > MaxTokenBytes || strings.TrimSpace(token) != token {
		return p, ErrPermit
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return p, ErrPermit
	}
	body, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if decodeErr != nil || len(body) > 192<<10 || signatureErr != nil || !ed25519.Verify(public, append([]byte(domain), body...), signature) {
		return p, ErrPermit
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.ControllerID != controller || p.Action != action || p.Validate(now) != nil {
		return Permit{}, ErrPermit
	}
	return p, nil
}
