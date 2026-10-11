package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const toolConfirmationDomain = "agentplug/tool-confirmation/v1\x00"

// ToolConfirmationClaims describes an approval from the separate human
// control plane. Agents and model providers must never possess its signing key.
// Confirmation does not grant resource access; current IAM checks remain required.
type ToolConfirmationClaims struct {
	Version            string `json:"version"`
	ApprovalID         string `json:"approval_id"`
	ActorID            string `json:"actor_id"`
	ScopeHash          string `json:"scope_hash"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	PolicyHash         string `json:"policy_hash"`
	ToolName           string `json:"tool_name"`
	CallID             string `json:"call_id"`
	Fingerprint        string `json:"fingerprint"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"`
	PendingKey         string `json:"pending_key,omitempty"`
	CheckpointRevision uint64 `json:"checkpoint_revision,omitempty"`
}

func validPendingConfirmationReference(claims ToolConfirmationClaims) bool {
	return claims.PendingKey == "" && claims.CheckpointRevision == 0 ||
		stateName.MatchString(claims.PendingKey) && claims.CheckpointRevision >= 1 && claims.CheckpointRevision <= 64
}

type ToolConfirmationVerifier struct{ publicKey ed25519.PublicKey }

func NewToolConfirmationVerifier(public ed25519.PublicKey) (*ToolConfirmationVerifier, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid tool confirmation verification key")
	}
	return &ToolConfirmationVerifier{publicKey: append(ed25519.PublicKey(nil), public...)}, nil
}

func (v *ToolConfirmationVerifier) Verify(token string, scope sharedkernel.Scope, policyHash, name, callID, fingerprint string, now time.Time) error {
	denied := errors.New("tool confirmation denied")
	if v == nil || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || len(token) > 8192 || token == "" || strings.TrimSpace(token) != token {
		return denied
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return denied
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(body) > 4096 {
		return denied
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || !ed25519.Verify(v.publicKey, append([]byte(toolConfirmationDomain), body...), signature) {
		return denied
	}
	var claims ToolConfirmationClaims
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil || decoder.Decode(new(any)) != io.EOF {
		return denied
	}
	if claims.Version != "tool-confirmation/v1" || claims.ApprovalID == "" || len(claims.ApprovalID) > 128 || claims.ActorID != scope.PrincipalID || claims.ScopeHash != ToolReceiptScopeHash(scope) || claims.AuthorizationEpoch != scope.AuthorizationEpoch || policyHash == "" || claims.PolicyHash != policyHash || claims.ToolName != name || callID == "" || claims.CallID != callID || fingerprint == "" || claims.Fingerprint != fingerprint {
		return denied
	}
	if claims.IssuedAt <= 0 || claims.IssuedAt > now.Unix()+5 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 300 || now.Unix() >= claims.ExpiresAt {
		return denied
	}
	if !validPendingConfirmationReference(claims) {
		return denied
	}
	return nil
}

func (m *Module) SetToolConfirmationVerifier(verifier *ToolConfirmationVerifier) {
	m.toolConfirmation = verifier
}

func (m *Module) SetToolConfirmationAuthority(authority ToolConfirmationAuthority) {
	m.toolConfirmationAuthority = authority
}

func (m *Module) checkToolConfirmation(ctx context.Context, token string, scope sharedkernel.Scope, policyHash, name, callID, fingerprint string) error {
	if m.toolConfirmationAuthority == nil || m.toolConfirmation.Verify(token, scope, policyHash, name, callID, fingerprint, time.Now()) != nil {
		return ErrToolApprovalDenied
	}
	body, _ := base64.RawURLEncoding.Strict().DecodeString(strings.Split(token, ".")[0])
	var claims ToolConfirmationClaims
	if json.Unmarshal(body, &claims) != nil {
		return ErrToolApprovalDenied
	}
	return m.toolConfirmationAuthority.CheckApproval(ctx, claims)
}

func toolRequiresConfirmation(policy []string, name string) bool {
	for _, tool := range policy {
		if tool == name {
			return true
		}
	}
	return false
}
